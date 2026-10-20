"""Connections made of several programs.

An Aether profile, and any chain, runs as a *stack*: one process per hop, started in the order the
traffic travels, each one dialling out through the loopback proxy of the one before it:

    you -> [front] -> hop N -> ... -> hop 2 -> hop 1 -> the internet
                                      (started last)  (started first)

Only the last process listens where the user asked (address, ports, login, route preset); the
others listen on loopback ports v2rm picks. A small Xray "front" is added in front of an Aether
hop when v2rm's login or route presets are wanted, because Aether's own SOCKS5 port has neither.

This module plans a stack (pure: nothing is started, so the tests can look at every decision)
and runs one. `v2rm.process.supervisor` owns the state files that make a stack survive the CLI
that started it.
"""

from __future__ import annotations

import contextlib
import json
import os
import signal
import socket
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from v2rm.constants import (
    AETHER_POLL_INTERVAL,
    AETHER_START_TIMEOUT,
    CONNECT_POLL_INTERVAL,
    CONNECT_POLL_TIMEOUT,
    DISCONNECT_GRACE_SECONDS,
)
from v2rm.engines import generate_config, needs_preflight, resolve_engine
from v2rm.engines.aether import files as aether_files
from v2rm.engines.aether.env import build_environment, scrubbed_environment
from v2rm.engines.xray.generate import generate_front_config
from v2rm.errors import (
    ConnectFailedError,
    ProfileNotFoundError,
    ProfileValidationError,
)
from v2rm.models.auth import ProxyAuth
from v2rm.models.chain import ChainHop
from v2rm.models.enums import EngineKind, Protocol
from v2rm.models.profile import Profile
from v2rm.net.addresses import hostport
from v2rm.net.ports import free_port
from v2rm.net.proxy_url import ProxyEndpoint, parse_proxy_url, redact
from v2rm.parsers.aether import validate_settings
from v2rm.process import supervisor
from v2rm.routing.model import RoutePlan
from v2rm.routing.presets import GLOBAL
from v2rm.store import paths

# How a stage says it is up.
READY_PORT = "port"  # the port accepts connections (Xray, sing-box)
READY_SOCKS5 = "socks5"  # the port answers a SOCKS5 greeting (Aether)

# A chain is a process per hop; more than this is a mistake, not a setup.
MAX_PROFILE_HOPS = 5

ENV_START_TIMEOUT = "V2RM_AETHER_START_TIMEOUT"

Progress = Callable[[str], None]

# How long Aether may say nothing before v2rm reports that it is still waiting.
HEARTBEAT_SECONDS = 20.0


# ---- the plan -----------------------------------------------------------------------------------


@dataclass
class Stage:
    """One program of a stack."""

    label: str
    engine: EngineKind
    socks_port: int
    listen: str = "127.0.0.1"
    http_port: int | None = None
    # The one that listens where the user asked.
    user_facing: bool = False
    # Xray / sing-box: the JSON config, the profile it runs (None for a front) and whether to
    # check the config with the engine's own `-test` first.
    config: dict[str, Any] | None = None
    profile: Profile | None = None
    preflight: bool = False
    # Aether: the environment it is started with, and the folder it keeps its identities in.
    env: dict[str, str] = field(default_factory=dict)
    workdir: Path | None = None
    ready: str = READY_PORT
    ready_timeout: float = CONNECT_POLL_TIMEOUT


@dataclass
class StackPlan:
    stages: list[Stage]  # in the order they are started: the first hop first, what the user talks to last
    notes: list[str] = field(default_factory=list)
    hops: list[str] = field(default_factory=list)  # what the user chained, in traffic order
    aether_ids: list[str] = field(default_factory=list)  # whose WARP identities are in use

    @property
    def user_facing(self) -> Stage:
        return next(stage for stage in self.stages if stage.user_facing)

    def description(self) -> str:
        return " -> ".join(self.hops)


@dataclass(frozen=True)
class ProfileHop:
    profile: Profile


@dataclass(frozen=True)
class ProxyHop:
    endpoint: ProxyEndpoint


Hop = ProfileHop | ProxyHop


def uses_stack(profile: Profile) -> bool:
    """Whether connecting this profile takes the multi-process path."""
    return profile.protocol in (Protocol.AETHER, Protocol.CHAIN)


def _find_member(store: Any, hop: ChainHop, chain: Profile) -> Profile:
    member = store.get(hop.ref) if hop.ref else None
    if member is not None:
        return member
    # The profile may have been re-created under a new id (a subscription refresh does that).
    same_name = [p for p in store.list() if hop.name and p.name == hop.name]
    if len(same_name) == 1:
        return same_name[0]
    raise ProfileNotFoundError(
        f"The chain '{chain.name}' uses the profile '{hop.label()}', which no longer exists"
        + (" (or there are several with that name)" if len(same_name) > 1 else "")
        + f". Remove the chain with `v2rm profile remove {chain.id}` or make it again."
    )


def resolve_hops(profile: Profile, store: Any, _trail: tuple[str, ...] = ()) -> list[Hop]:
    """The hops a profile stands for, in the order the traffic travels. A plain profile is one
    hop; a chain is its members, with any chain among them unfolded."""
    if not profile.is_chain:
        return [ProfileHop(profile)]
    if profile.id in _trail:
        raise ProfileValidationError(f"The chain '{profile.name}' contains itself")
    hops: list[Hop] = []
    for hop in profile.chain or []:
        if hop.is_proxy:
            hops.append(ProxyHop(parse_proxy_url(hop.ref)))
        else:
            hops.extend(resolve_hops(_find_member(store, hop, profile), store, (*_trail, profile.id)))
    return hops


def check_composition(hops: list[Hop], name: str) -> None:
    """The rules a chain has to follow to be runnable."""
    members = [h for h in hops if isinstance(h, ProfileHop)]
    if not members:
        raise ProfileValidationError(f"'{name}' has no connection in it: a proxy alone is not a chain")
    if len(members) > MAX_PROFILE_HOPS:
        raise ProfileValidationError(
            f"'{name}' has {len(members)} hops; at most {MAX_PROFILE_HOPS} are supported "
            "(every hop is a program running beside the others)"
        )

    for index, hop in enumerate(hops):
        if isinstance(hop, ProxyHop):
            if index != 0:
                raise ProfileValidationError(
                    f"'{name}': a proxy address can only be the first hop. Everything leaves through it, "
                    "and nothing can carry v2rm's connection to it from inside the chain."
                )
            continue
        member = hop.profile
        if member.is_raw and index != 0:
            raise ProfileValidationError(
                f"'{name}': the raw Xray config '{member.name}' has outbounds of its own that v2rm can't "
                "safely re-route through another hop, so it can only be the first hop of a chain."
            )
        if member.is_aether and index > 0 and member.aether and member.aether.upstream:
            raise ProfileValidationError(
                f"'{name}': '{member.name}' already has an upstream proxy of its own "
                f"({redact(member.aether.upstream)}), and in this chain it would be dialled through the "
                "previous hop instead. Remove its upstream, or make it the first hop."
            )

    seen: set[str] = set()
    for hop in members:
        if hop.profile.is_aether:
            if hop.profile.id in seen:
                raise ProfileValidationError(
                    f"'{name}': '{hop.profile.name}' appears twice, and two tunnels can't share one WARP identity"
                )
            seen.add(hop.profile.id)


FIRST_CONNECTION = "First connection of"


def registration_note(member: Profile) -> str | None:
    """Said before a profile whose WARP identity does not exist yet is started: Aether is about
    to register a device with Cloudflare, which is a network call the user should expect."""
    settings = member.aether
    if settings is None:
        return None
    registered, needed = aether_files.identity_state(aether_files.config_path(member.id), settings.mode)
    if registered >= needed:
        return None
    return (
        f"{FIRST_CONNECTION} '{member.name}': Aether registers a free anonymous Cloudflare WARP device "
        "for it (keys are kept under your v2rm data folder). That needs api.cloudflareclient.com to be reachable."
    )


def aether_start_timeout() -> float:
    raw = os.environ.get(ENV_START_TIMEOUT, "").strip()
    try:
        value = float(raw) if raw else AETHER_START_TIMEOUT
    except ValueError:
        value = AETHER_START_TIMEOUT
    return max(value, 5.0)


def aether_profile_ids(profile: Profile, store: Any) -> list[str]:
    """The Aether profiles a connection would run (they own WARP identities, which two live
    tunnels must not share)."""
    if not uses_stack(profile):
        return []
    try:
        hops = resolve_hops(profile, store)
    except (ProfileNotFoundError, ProfileValidationError):
        return []
    return [h.profile.id for h in hops if isinstance(h, ProfileHop) and h.profile.is_aether]


def plan_stack(
    profile: Profile,
    store: Any,
    *,
    preferred_engine: EngineKind | None,
    route_plan: RoutePlan,
    socks_port: int,
    http_port: int,
    listen_address: str = "127.0.0.1",
    auth: ProxyAuth | None = None,
    ports: Callable[..., int] = free_port,
) -> StackPlan:
    """Decide what to run for an Aether profile or a chain, without running anything."""
    hops = resolve_hops(profile, store)
    check_composition(hops, profile.name)

    plan = StackPlan(stages=[])
    previous: ProxyEndpoint | None = None
    start = 0
    if isinstance(hops[0], ProxyHop):
        previous = hops[0].endpoint
        plan.hops.append(redact(previous.url()))
        start = 1

    members = [h.profile for h in hops[start:] if isinstance(h, ProfileHop)]
    for index, member in enumerate(members):
        last = index == len(members) - 1
        engine, _ = resolve_engine(member, preferred_engine)
        plan.hops.append(member.name)
        if engine == EngineKind.AETHER:
            previous = _plan_aether(plan, member, last, previous, route_plan, socks_port, http_port, listen_address, auth, ports)
        else:
            previous = _plan_engine(
                plan, member, engine, last, previous, route_plan, socks_port, http_port, listen_address, auth, ports
            )
    return plan


def _loopback(port: int) -> ProxyEndpoint:
    return ProxyEndpoint("socks5", "127.0.0.1", port)


def _plan_engine(
    plan: StackPlan,
    member: Profile,
    engine: EngineKind,
    last: bool,
    previous: ProxyEndpoint | None,
    route_plan: RoutePlan,
    socks_port: int,
    http_port: int,
    listen_address: str,
    auth: ProxyAuth | None,
    ports: Callable[..., int],
) -> ProxyEndpoint:
    """An Xray or sing-box hop. The last one is what the user connects to; the others listen on
    loopback with no login and no route preset (those belong to the last)."""
    if last:
        own_socks, own_http, listen, hop_auth, hop_routes = socks_port, http_port, listen_address, auth, route_plan
    else:
        own_socks = ports()
        own_http = ports(avoid=own_socks)
        listen, hop_auth, hop_routes = "127.0.0.1", None, GLOBAL

    notes: list[str] = []
    config = generate_config(
        engine, member, hop_routes, own_socks, own_http, listen_address=listen, auth=hop_auth, notes=notes,
        upstream=previous,
    )
    plan.notes.extend(notes)
    plan.stages.append(
        Stage(
            label=f"{member.name} ({engine.value})",
            engine=engine,
            socks_port=own_socks,
            http_port=own_http,
            listen=listen,
            user_facing=last,
            config=config,
            profile=member,
            # A chained config is new territory for the engine: have it check the file first.
            preflight=needs_preflight(engine, member) or previous is not None,
            ready_timeout=CONNECT_POLL_TIMEOUT,
        )
    )
    return _loopback(own_socks)


def _plan_aether(
    plan: StackPlan,
    member: Profile,
    last: bool,
    previous: ProxyEndpoint | None,
    route_plan: RoutePlan,
    socks_port: int,
    http_port: int,
    listen_address: str,
    auth: ProxyAuth | None,
    ports: Callable[..., int],
) -> ProxyEndpoint:
    settings = member.aether
    if settings is None:
        raise ProfileValidationError(f"'{member.name}' is an Aether profile without any Aether settings")
    validate_settings(settings)

    # Aether's own SOCKS5 port has no login and no geo rules. When v2rm's are wanted, Aether goes
    # on loopback and a small Xray front serves them; otherwise Aether listens where the user asked.
    front = last and (auth is not None or bool(route_plan.rules))
    direct = last and not front

    if direct:
        own_socks, own_http, listen = socks_port, http_port, listen_address
        socks, http = hostport(listen, own_socks), hostport(listen, own_http)
    else:
        own_socks, own_http, listen = ports(), None, "127.0.0.1"
        socks, http = hostport(listen, own_socks), None

    upstream = previous
    if upstream is None and settings.upstream:
        upstream = parse_proxy_url(settings.upstream)

    notes: list[str] = []
    env = build_environment(
        settings,
        config_path=aether_files.config_path(member.id),
        socks=socks,
        http=http,
        upstream=upstream,
        chained=previous is not None,
        notes=notes,
    )
    plan.notes.extend(notes)

    note = registration_note(member)
    if note:
        plan.notes.append(note)

    plan.aether_ids.append(member.id)
    plan.stages.append(
        Stage(
            label=f"{member.name} (aether)",
            engine=EngineKind.AETHER,
            socks_port=own_socks,
            http_port=own_http,
            listen=listen,
            user_facing=direct,
            env=env,
            profile=member,
            workdir=paths.aether_profile_dir(member.id),
            ready=READY_SOCKS5,
            ready_timeout=float(settings.wait_secs) if settings.wait_secs else aether_start_timeout(),
        )
    )

    if front:
        plan.stages.append(
            Stage(
                label="front (xray): login and route preset",
                engine=EngineKind.XRAY,
                socks_port=socks_port,
                http_port=http_port,
                listen=listen_address,
                user_facing=True,
                ready_timeout=CONNECT_POLL_TIMEOUT,
                # A preset's geosite:/geoip: tags need the geo data: have Xray say so before it starts.
                preflight=bool(route_plan.rules),
                config=generate_front_config(
                    route_plan, socks_port, http_port, _loopback(own_socks), listen_address=listen_address, auth=auth
                ),
            )
        )
        plan.notes.append(
            "Xray serves the login / route preset in front of Aether (Aether's own SOCKS5 port has neither)."
        )
    return _loopback(own_socks)


# ---- running a stack ----------------------------------------------------------------------------


@dataclass
class Running:
    """A started stage."""

    stage: Stage
    proc: Any
    log_path: Path
    config_path: Path | None = None

    @property
    def pid(self) -> int:
        return int(self.proc.pid)


def stage_command(stage: Stage, binary: Path, config_path: Path | None) -> list[str]:
    """The command line of a stage. Aether takes everything from its environment."""
    if stage.engine == EngineKind.AETHER:
        return [str(binary)]
    return [str(binary), "run", "-c", str(config_path)]


def stage_environment(stage: Stage) -> dict[str, str]:
    if stage.engine == EngineKind.AETHER:
        return {**scrubbed_environment(dict(os.environ)), **stage.env}
    env = dict(os.environ)
    env["XRAY_LOCATION_ASSET"] = str(paths.geo_assets_dir())
    return env


def rotate_log(log_path: Path) -> None:
    if log_path.exists():
        rotated = log_path.with_name(log_path.name + ".1")
        with contextlib.suppress(OSError):
            rotated.unlink()
        with contextlib.suppress(OSError):
            log_path.rename(rotated)


def spawn(argv: list[str], env: dict[str, str], cwd: Path | None, log_path: Path) -> subprocess.Popen:
    """Start a program detached from this terminal, its output going to a log file. Its stdin is
    closed: a program that sees a terminal there (Aether does) may stop to ask a question."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    rotate_log(log_path)
    kwargs: dict[str, Any] = {"stdin": subprocess.DEVNULL, "stderr": subprocess.STDOUT, "env": env}
    if cwd is not None:
        cwd.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError):
            os.chmod(cwd, 0o700)
        kwargs["cwd"] = str(cwd)
    if os.name == "posix":
        kwargs["start_new_session"] = True
    with log_path.open("wb") as log_fh:
        return supervisor.track(subprocess.Popen(argv, stdout=log_fh, **kwargs))


def socks5_ready(host: str, port: int, timeout: float = 1.0) -> bool:
    """Whether something answers a SOCKS5 greeting there. A bare TCP connect is not enough for
    Aether: at start-up it binds its SOCKS port for a moment just to see it is free, and only
    opens it for real once the tunnel has been proven to carry data."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(b"\x05\x01\x00")
            return sock.recv(2) == b"\x05\x00"
    except OSError:
        return False


def _is_ready(stage: Stage) -> bool:
    host = supervisor.client_address(stage.listen)
    if stage.ready == READY_SOCKS5:
        return socks5_ready(host, stage.socks_port)
    return supervisor._port_open(stage.socks_port, host=host)


class LogFollower:
    """Reads a growing log file a bit at a time, for showing progress."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._offset = 0
        self._partial = ""

    def new_lines(self) -> list[str]:
        try:
            with self._path.open("rb") as fh:
                fh.seek(self._offset)
                chunk = fh.read()
                self._offset = fh.tell()
        except OSError:
            return []
        text = self._partial + chunk.decode("utf-8", errors="replace")
        *lines, self._partial = text.split("\n")
        return [line.rstrip("\r") for line in lines if line.strip()]


def log_message(line: str) -> str:
    """Aether's log line without the env_logger prefix: `[2026-10-20T10:20:30.123Z INFO  aether] msg`."""
    if line.startswith("[") and "] " in line:
        prefix, _, rest = line.partition("] ")
        if " INFO " in prefix or " WARN " in prefix or " ERROR " in prefix or " DEBUG " in prefix:
            return rest.strip()
    return line.strip()


def is_progress_line(message: str) -> bool:
    """Aether's own stage markers: [+] done, [*] doing, [-] problem, [!] warning."""
    return message[:3] in ("[+]", "[*]", "[-]", "[!]")


def tail(log_path: Path, lines: int = 20) -> str:
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return "\n".join(text.splitlines()[-lines:])


def wait_ready(running: Running, progress: Progress | None) -> None:
    """Block until the stage is up, it dies, or its time is out."""
    stage = running.stage
    follower = LogFollower(running.log_path) if stage.engine == EngineKind.AETHER else None
    interval = AETHER_POLL_INTERVAL if stage.engine == EngineKind.AETHER else CONNECT_POLL_INTERVAL
    started = time.monotonic()
    deadline = started + stage.ready_timeout
    shown: set[str] = set()
    last_word = started

    def report() -> None:
        nonlocal last_word
        if follower is None or progress is None:
            return
        for line in follower.new_lines():
            message = log_message(line)
            if is_progress_line(message) and message not in shown:
                shown.add(message)
                progress(f"{stage.label}: {message[:160]}")
                last_word = time.monotonic()
        # A scan can go quiet for a long while; say it is still going rather than look hung.
        if time.monotonic() - last_word >= HEARTBEAT_SECONDS:
            last_word = time.monotonic()
            elapsed = last_word - started
            progress(f"{stage.label}: still working ({elapsed:.0f} s of up to {stage.ready_timeout:.0f} s)...")

    while True:
        code = running.proc.poll()
        if code is not None:
            report()
            raise ConnectFailedError(
                f"{stage.label} exited (code {code}) before it was ready. Last log lines:\n{tail(running.log_path)}"
            )
        if _is_ready(stage):
            report()
            return
        report()
        if time.monotonic() >= deadline:
            raise ConnectFailedError(
                f"{stage.label} was not ready on port {stage.socks_port} after {stage.ready_timeout:.0f} s. "
                f"Last log lines:\n{tail(running.log_path)}"
            )
        time.sleep(interval)


def write_config(stage: Stage, path: Path) -> None:
    """The stage's JSON config, readable only by its owner: it holds server credentials."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(stage.config, indent=2), encoding="utf-8")
    with contextlib.suppress(OSError):
        os.chmod(path, 0o600)


def _signal_group(pid: int, sig: int) -> None:
    """Signal a stage and what it started (Aether may run Tor or Psiphon helpers). Stages are
    started in their own session, so the process is its group's leader; if for any reason it is
    not, only the process itself is signalled and never a group v2rm shares."""
    with contextlib.suppress(AttributeError, OSError):
        if os.getpgid(pid) == pid:
            os.killpg(pid, sig)
            return
    with contextlib.suppress(ProcessLookupError, OSError):
        os.kill(pid, sig)


def stop_pids(pids: list[int], grace: float = DISCONNECT_GRACE_SECONDS) -> None:
    """Ask each process to stop, in the order given, and kill what is still there after `grace`."""
    for pid in pids:
        _signal_group(pid, signal.SIGTERM)
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline and any(supervisor._is_alive(p) for p in pids):
        time.sleep(0.1)
    for pid in pids:
        if supervisor._is_alive(pid):
            _signal_group(pid, getattr(signal, "SIGKILL", signal.SIGTERM))


def stop_running(running: list[Running]) -> None:
    """Stop started stages, the one the user talks to first (the last one started)."""
    for item in reversed(running):
        if item.proc.poll() is None:
            with contextlib.suppress(ProcessLookupError, OSError):
                _signal_group(item.pid, signal.SIGTERM)
    deadline = time.monotonic() + DISCONNECT_GRACE_SECONDS
    while time.monotonic() < deadline and any(item.proc.poll() is None for item in running):
        time.sleep(0.1)
    for item in running:
        if item.proc.poll() is None:
            _signal_group(item.pid, getattr(signal, "SIGKILL", signal.SIGTERM))
            with contextlib.suppress(Exception):
                item.proc.wait(timeout=2)
