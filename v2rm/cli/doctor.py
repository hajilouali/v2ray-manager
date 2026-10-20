from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field

from rich.console import Console
from rich.markup import escape

from v2rm.coredl.install import current_version
from v2rm.errors import V2rmError
from v2rm.engines.aether.probe import aether_runs, looks_like_glibc_mismatch
from v2rm.engines.probe import probe_xray_features
from v2rm.engines.versioning import UPDATE_XRAY_HINT, compare_versions, raw_version_requirement
from v2rm.net import addresses
from v2rm.net.exposure import listen_warning, ufw_commands
from v2rm.net.firewall import BLOCKED, INACTIVE, OPEN, RESTRICTED, check_firewall
from v2rm.process import supervisor
from v2rm.store import paths
from v2rm.store.auth import AuthStore
from v2rm.store.profiles import ProfileStore
from v2rm.store.state import AppStateStore

console = Console()

GEO_FILES = ("geoip.dat", "geosite.dat")


@dataclass
class Check:
    ok: bool
    message: str
    hints: list[str] = field(default_factory=list)


def _engine_checks() -> list[Check]:
    checks: list[Check] = []
    for engine in ("xray", "singbox"):
        version = current_version(engine)
        checks.append(
            Check(True, f"{engine} installed ({version})")
            if version
            else Check(False, f"{engine} not installed -- run `v2rm core install {engine}`")
        )
    return checks


def _xray_checks() -> list[Check]:
    """What the installed Xray can do, the geo data it reads, and which of the
    stored profiles need a newer one."""
    version = current_version("xray")
    if not version:
        return []
    checks: list[Check] = []

    binary = paths.engine_binary_path("xray")
    if binary.exists():
        for probe in probe_xray_features(binary, paths.geo_assets_dir()):
            if probe.supported:
                checks.append(Check(True, f"Xray {probe.name}: supported ({probe.detail})"))
            elif probe.supported is False:
                checks.append(Check(False, f"Xray {probe.name}: not supported -- {probe.detail}", [UPDATE_XRAY_HINT]))
            else:
                checks.append(Check(False, f"Xray {probe.name}: {probe.detail}"))

    assets = paths.geo_assets_dir()
    present = [name for name in GEO_FILES if (assets / name).exists()]
    if len(present) == len(GEO_FILES):
        checks.append(Check(True, f"Geo data in {assets} ({', '.join(present)})"))
    else:
        missing = [name for name in GEO_FILES if name not in present]
        checks.append(
            Check(
                False,
                f"Geo data missing in {assets}: {', '.join(missing)} -- run `v2rm route update-data`",
                ["Xray needs it for geosite:/geoip: routing rules, including those in raw configs."],
            )
        )

    try:
        stored = ProfileStore().list()
    except (OSError, ValueError, KeyError, TypeError) as exc:
        checks.append(Check(False, f"Couldn't read the saved profiles, so their Xray version needs weren't checked ({exc})"))
        stored = []

    too_new = []
    for profile in stored:
        if not profile.is_raw:
            continue
        minimum, _ = raw_version_requirement(profile)
        if minimum and compare_versions(version, minimum) < 0:
            too_new.append((profile.name, minimum))
    if too_new:
        shown = ", ".join(f"{name} (needs >= {minimum})" for name, minimum in too_new[:5])
        more = f" and {len(too_new) - 5} more" if len(too_new) > 5 else ""
        checks.append(
            Check(
                False,
                f"{len(too_new)} profile(s) need a newer Xray-core than {version}: {shown}{more}",
                [UPDATE_XRAY_HINT],
            )
        )
    return checks


def _aether_checks() -> list[Check]:
    """Aether is optional: only a problem if an Aether profile (or a chain with one) needs it."""
    from v2rm.process import stack

    try:
        profiles = ProfileStore().list()
    except (OSError, ValueError, KeyError, TypeError):
        profiles = []
    needing = [p for p in profiles if p.is_aether]
    chains = [p for p in profiles if p.is_chain]
    version = current_version("aether")
    checks: list[Check] = []

    if not version:
        checks.append(
            Check(False, f"aether not installed, and {len(needing)} Aether profile(s) need it -- run `v2rm core install aether`")
            if needing
            else Check(True, "aether not installed (only needed for Aether profiles: `v2rm core install aether`)")
        )
    else:
        binary = paths.engine_binary_path("aether")
        runs, detail = aether_runs(binary) if binary.exists() else (False, "the binary is missing")
        if runs:
            checks.append(Check(True, f"aether installed ({version}); it runs ({detail})"))
        else:
            hints = []
            if looks_like_glibc_mismatch(detail):
                hints.append("This looks like a glibc build on an older system: `v2rm core install aether --variant musl` (static).")
            checks.append(Check(False, f"aether {version} is installed but cannot run: {detail}", hints))

    for chain in chains:
        try:
            stack.check_composition(stack.resolve_hops(chain, ProfileStore()), chain.name)
        except V2rmError as exc:
            checks.append(Check(False, f"Chain '{chain.name}' can't run: {exc}"))

    state = AppStateStore().load()
    try:
        auth = AuthStore().load()
    except V2rmError:
        auth = None
    wants_front = auth is not None or state.route_preset.value != "global"
    if needing and wants_front and not current_version("xray"):
        checks.append(
            Check(
                False,
                "A login or a route preset in front of Aether needs Xray-core, which is not installed",
                ["Run `v2rm core install xray`, or remove the login and use the global route preset."],
            )
        )
    return checks


def _listen_checks() -> list[Check]:
    state = AppStateStore().load()
    listen = state.listen_address
    ports = (state.socks_port, state.http_port)
    checks = [Check(True, f"SOCKS port {state.socks_port}, HTTP port {state.http_port}")]

    try:
        auth = AuthStore().load()
    except V2rmError as exc:  # fails closed everywhere else; here it is just something to report
        auth = None
        checks.append(Check(False, str(exc)))

    warning = listen_warning(listen)
    if warning is None:
        checks.append(Check(True, "Listening on 127.0.0.1 (localhost only)"))
        return checks

    checks.append(Check(False, warning))
    if not addresses.is_wildcard(listen) and not addresses.local_address_exists(listen):
        checks.append(
            Check(
                False,
                f"This host has no address {listen} right now, so the proxy can't start "
                "(a Docker bridge address only exists while Docker is running)",
            )
        )

    allow, deny = ufw_commands(listen, *ports)
    firewall_hints = [f"  {allow}", f"  {deny}   # only needed if your default policy allows incoming traffic"]

    if auth is not None:
        checks.append(Check(True, f"Login required on both ports (user: {auth.user})"))
    else:
        checks.append(
            Check(
                False,
                "No login is required -- anything that can reach the proxy can use it",
                ["Require one with `v2rm port set --auth USER:PASS`, or restrict it with a firewall, for example (ufw):"]
                + firewall_hints,
            )
        )

    report = check_firewall(ports)
    if report.state == RESTRICTED:
        checks.append(Check(True, f"Firewall ({report.tool}): {report.detail}"))
    elif report.state == OPEN:
        checks.append(Check(False, f"Firewall ({report.tool}): {report.detail}"))
    elif report.state == BLOCKED:
        checks.append(
            Check(
                False,
                f"Firewall ({report.tool}): {report.detail} -- containers can't connect until you allow them",
                ["For example:", firewall_hints[0]],
            )
        )
    elif report.state == INACTIVE:
        checks.append(Check(False, f"Firewall: {report.detail}"))
    else:
        checks.append(
            Check(
                False,
                f"Firewall: couldn't determine whether these ports are restricted ({report.detail})",
                ["Check it yourself, e.g. `sudo ufw status verbose` or `sudo iptables -S INPUT`."],
            )
        )
    return checks


def collect_checks() -> list[Check]:
    checks: list[Check] = []

    is_linux = sys.platform.startswith("linux")
    checks.append(
        Check(True, f"Running on Linux ({sys.platform})")
        if is_linux
        else Check(False, f"Not running on Linux ({sys.platform}) -- v2rm targets Linux only")
    )

    checks.extend(_engine_checks())
    checks.extend(_xray_checks())
    checks.extend(_aether_checks())

    connected, pid = supervisor.is_connected()
    checks.append(Check(True, f"Connected (pid {pid})" if connected else "Not connected"))
    if connected:
        info = supervisor.status()
        if info.get("degraded"):
            stopped = [m for m in info.get("stack", []) if not m.get("alive")]
            checks.append(
                Check(
                    False,
                    "A program of the connection has stopped: " + ", ".join(str(m.get("label")) for m in stopped),
                    [f"See its log: {m.get('log')}" for m in stopped] + ["`v2rm connect` starts everything again."],
                )
            )
        if info.get("listening") is False and info.get("state") != "starting":
            checks.append(
                Check(
                    False,
                    f"The engine is running but nothing is accepting connections on port {info.get('socks_port')}",
                    [f"See its log: {paths.engine_log_file()}"],
                )
            )

    checks.extend(_listen_checks())
    state = AppStateStore().load()
    checks.append(Check(True, f"Route preset: {state.route_preset.value}"))

    editor = os.environ.get("EDITOR")
    checks.append(
        Check(True, f"$EDITOR is set ({editor})")
        if editor
        else Check(False, "$EDITOR is not set -- `profile edit`/`route edit` will fall back to nano")
    )

    for name, path in (("config", paths.config_dir()), ("data", paths.data_dir()), ("state", paths.state_dir())):
        writable = os.access(path, os.W_OK) if path.exists() else True
        checks.append(
            Check(True, f"{name} dir writable ({path})")
            if writable
            else Check(False, f"{name} dir NOT writable ({path})")
        )
    return checks


def doctor_command() -> None:
    """Check the environment: platform, engines (and what Xray supports), geo data, ports,
    who can reach the proxy, and the firewall."""
    for check in collect_checks():
        icon = "[green]ok[/green]  " if check.ok else "[yellow]warn[/yellow]"
        console.print(f"{icon} {escape(check.message)}")
        for hint in check.hints:
            console.print(f"       [dim]{escape(hint)}[/dim]")
