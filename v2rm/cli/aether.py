"""`v2rm aether`: helpers around Aether profiles -- register a WARP identity without connecting,
see (and forget) the gateways Aether remembers for quick reconnects, and show exactly what v2rm
hands to the Aether program."""

from __future__ import annotations

import os
import subprocess

import typer
from rich.console import Console
from rich.markup import escape

from v2rm.engines.aether import files as aether_files
from v2rm.engines.aether.env import build_environment, describe_environment, scrubbed_environment
from v2rm.errors import EngineNotInstalledError, V2rmError
from v2rm.models.aether import AetherMode
from v2rm.models.enums import EngineKind
from v2rm.models.profile import Profile
from v2rm.net.proxy_url import parse_proxy_url
from v2rm.process import stack, supervisor
from v2rm.store import paths
from v2rm.store.profiles import ProfileStore
from v2rm.store.state import AppStateStore

console = Console()
aether_app = typer.Typer(help="Aether (Cloudflare WARP) helpers: register identities, remembered gateways, environment.")

_REGISTER_WHICH = {
    AetherMode.MASQUE: "masque",
    AetherMode.WG: "wg",
    AetherMode.GOOL: "gool",
    AetherMode.GOOL_CLASSIC: "gool-classic",
    AetherMode.MIM: "mim",
}


def _aether_profile(ref: str) -> Profile:
    profile = ProfileStore().resolve(ref)
    if not profile.is_aether or profile.aether is None:
        raise V2rmError(f"'{profile.name}' is not an Aether profile (see `v2rm add aether`).")
    return profile


def _environment(profile: Profile, extra: dict[str, str] | None = None) -> dict[str, str]:
    """The environment for a run of this profile on its own, listening on a throwaway loopback
    address (the commands here never open a proxy)."""
    assert profile.aether is not None
    upstream = parse_proxy_url(profile.aether.upstream) if profile.aether.upstream else None
    env = build_environment(
        profile.aether,
        config_path=aether_files.config_path(profile.id),
        socks="127.0.0.1:1819",
        upstream=upstream,
        notes=[],
    )
    env.update(extra or {})
    return env


@aether_app.command("register")
def register_command(
    ref: str = typer.Argument(..., help="Aether profile id or name."),
    timeout: int = typer.Option(180, "--timeout", help="Seconds to wait for the registration."),
) -> None:
    """Register the profile's WARP identity with Cloudflare now, without opening a tunnel.

    This creates a free anonymous WARP device (and, for gool, the keys inside it) and saves its
    keys under v2rm's data folder; a connection does the same on first use. The calls go to
    api.cloudflareclient.com, through the profile's upstream proxy if it has one."""
    profile = _aether_profile(ref)
    settings = profile.aether
    assert settings is not None
    try:
        binary = supervisor._binary_path(EngineKind.AETHER)
    except EngineNotInstalledError as exc:
        raise V2rmError(str(exc)) from exc

    base = aether_files.config_path(profile.id)
    registered, needed = aether_files.identity_state(base, settings.mode)
    if registered == needed:
        console.print(f"[dim]'{escape(profile.name)}' already has all {needed} identity file(s); Aether keeps what exists.[/dim]")
    console.print(f"Registering a free anonymous Cloudflare WARP device for '{escape(profile.name)}'...")

    base.parent.mkdir(parents=True, exist_ok=True)
    env = {
        **scrubbed_environment(dict(os.environ)),
        **_environment(profile, {"AETHER_REGISTER": _REGISTER_WHICH[settings.mode]}),
    }
    try:
        proc = subprocess.run(
            [str(binary)],
            env=env,
            cwd=str(base.parent),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise V2rmError(f"Registration did not finish within {timeout} s. Is api.cloudflareclient.com reachable?") from None
    except OSError as exc:
        raise V2rmError(f"Could not run Aether: {exc}") from exc

    for line in (proc.stdout or "").splitlines():
        message = stack.log_message(line)
        if stack.is_progress_line(message):
            console.print(f"  [dim]{escape(message[:160])}[/dim]")
    if proc.returncode != 0:
        tail = "\n".join((proc.stdout or "").splitlines()[-10:])
        raise V2rmError(f"Aether could not register (exit code {proc.returncode}):\n{tail}")

    registered, needed = aether_files.identity_state(base, settings.mode)
    console.print(f"[green]Registered[/green] {registered}/{needed} identity file(s) in {escape(str(base.parent))}")


@aether_app.command("gateways")
def gateways_command(
    ref: str = typer.Argument(..., help="Aether profile id or name."),
    forget: bool = typer.Option(False, "--forget", help="Forget the remembered gateways, so the next start scans afresh."),
) -> None:
    """Show the identities and the gateways Aether remembers for quick reconnects."""
    profile = _aether_profile(ref)
    settings = profile.aether
    assert settings is not None
    base = aether_files.config_path(profile.id)

    registered, needed = aether_files.identity_state(base, settings.mode)
    console.print(f"[bold]{escape(profile.name)}[/bold] [dim]({escape(settings.label)})[/dim]")
    console.print(f"  identities  {registered}/{needed} registered  [dim]({escape(str(base.parent))})[/dim]")

    cache_file = aether_files.lastconn_file(base, settings.mode)
    if cache_file is None:
        console.print(
            f"  gateways    [dim]Aether keeps no memory of gateways in {settings.mode.value} mode; "
            "pin the hops with `--outer`/`--inner` to skip the scan[/dim]"
        )
        return
    if forget:
        gone = aether_files.forget_last_gateways(cache_file)
        console.print("  gateways    forgotten -- the next start scans afresh" if gone else "  gateways    [dim]nothing to forget[/dim]")
        return
    cache = aether_files.read_last_gateways(cache_file)
    if cache is None:
        console.print("  gateways    [dim]none remembered yet (the first successful connection saves one)[/dim]")
        return
    console.print(f"  last good   {escape(cache.peer)}  [dim]({escape(cache.carrier or 'carrier unknown')}, noize {escape(cache.profile or '?')})[/dim]")
    for peer in cache.recent:
        console.print(f"              {escape(peer)}")
    state = "on" if settings.quick_reconnect else "off"
    console.print(f"  quick reconnect is {state} for this profile.")


@aether_app.command("env")
def env_command(ref: str = typer.Argument(..., help="Aether profile id or name.")) -> None:
    """Print the environment variables v2rm gives Aether for this profile (secrets hidden), for
    checking a setting or reproducing a run by hand."""
    profile = _aether_profile(ref)
    state = AppStateStore().load()
    assert profile.aether is not None
    notes: list[str] = []
    upstream = parse_proxy_url(profile.aether.upstream) if profile.aether.upstream else None
    env = build_environment(
        profile.aether,
        config_path=aether_files.config_path(profile.id),
        socks=f"{state.listen_address}:{state.socks_port}",
        http=f"{state.listen_address}:{state.http_port}",
        upstream=upstream,
        notes=notes,
    )
    typer.echo(f"# environment for the `aether` program ({paths.engine_binary_path('aether')})")
    typer.echo("# v2rm sets these and removes every other AETHER_* variable and RUST_LOG from what Aether inherits.")
    for line in describe_environment(env):
        typer.echo(line)
    for note in notes:
        typer.echo(f"# note: {note}")
