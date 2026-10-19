from __future__ import annotations

import typer
from rich.console import Console
from rich.markup import escape

from v2rm.cli.exposure import print_exposure_warnings
from v2rm.engines import resolve_engine
from v2rm.errors import V2rmError
from v2rm.models.enums import RoutePreset
from v2rm.net.addresses import ensure_listen_address_available
from v2rm.process import supervisor
from v2rm.routing.model import RoutePlan
from v2rm.routing.presets import get_builtin
from v2rm.store import paths
from v2rm.store.auth import AuthStore
from v2rm.store.profiles import ProfileStore
from v2rm.store.state import AppStateStore

console = Console()

RAW_ROUTING_NOTE = (
    "Routing: this raw config uses its own routing rules; v2rm's route presets are not applied to raw configs."
)


def connect_command(
    profile_ref: str | None = typer.Argument(
        None, help="Profile id or name to connect. Omit to reconnect using the active profile."
    ),
) -> None:
    """Connect: (re)generate the engine config and start the local SOCKS/HTTP proxy."""
    state_store = AppStateStore()
    state = state_store.load()
    profile_store = ProfileStore()

    if profile_ref:
        profile = profile_store.resolve(profile_ref)
    elif state.active_profile_id:
        profile = profile_store.resolve(state.active_profile_id)
    else:
        raise V2rmError(
            "No active profile. Run `v2rm connect <profile>` or `v2rm profile use <profile>` first."
        )

    # Raw/MASQUE profiles run on Xray and Hysteria2/TUIC on sing-box whatever the
    # default engine is -- with a note rather than a failure. The saved default
    # (`v2rm core use`) is never changed by connecting.
    engine, engine_note = resolve_engine(profile, state.active_engine)
    route_plan = _resolve_route_plan(state.route_preset)
    auth = AuthStore().load()

    ensure_listen_address_available(state.listen_address)

    notes = supervisor.connect(
        profile,
        engine,
        route_plan,
        state.socks_port,
        state.http_port,
        listen_address=state.listen_address,
        auth=auth,
    )
    state.active_profile_id = profile.id
    state_store.save(state)

    login = ", login required" if auth else ""
    console.print(
        f"[green]Connected[/green] via {engine.value} -> {escape(profile.name)} "
        f"[dim](socks {state.listen_address}:{state.socks_port}, http {state.listen_address}:{state.http_port}{login})[/dim]"
    )
    if engine_note:
        console.print(f"[dim]{escape(engine_note)}[/dim]")
    for note in notes:
        console.print(f"[yellow]Note:[/yellow] {escape(note)}")
    if profile.is_raw:
        console.print(f"[dim]{escape(RAW_ROUTING_NOTE)}[/dim]")
    print_exposure_warnings(console, state.listen_address, auth is not None, state.socks_port, state.http_port)


def disconnect_command() -> None:
    """Disconnect the local SOCKS/HTTP proxy."""
    supervisor.disconnect()
    console.print("[green]Disconnected.[/green]")


def status_command() -> None:
    """Show the current connection status."""
    info = supervisor.status()
    if not info.get("connected"):
        console.print("[yellow]Not connected.[/yellow]")
        return

    listen = info.get("listen_address", "127.0.0.1")
    authenticated = bool(info.get("authenticated"))
    kind = info.get("profile_kind")
    console.print("[bold green]Connected[/bold green]")
    console.print(f"  profile   {escape(str(info.get('profile_name', '?')))}" + (f" [dim]({kind})[/dim]" if kind else ""))
    console.print(f"  engine    {info.get('engine', '?')}")
    console.print(f"  pid       {info.get('pid')}")
    console.print(f"  socks     {listen}:{info.get('socks_port')}")
    console.print(f"  http      {listen}:{info.get('http_port')}")
    console.print(f"  login     {'required' if authenticated else 'none'}")
    if kind == "raw":
        console.print("  routing   the config's own rules [dim](route presets are not applied to raw configs)[/dim]")
    else:
        console.print(f"  routing   {AppStateStore().load().route_preset.value}")
    if info.get("listening") is False:
        console.print(
            f"  [red]The engine is running but nothing is accepting connections on {listen}:{info.get('socks_port')}.[/red] "
            f"[dim]Its log: {paths.engine_log_file()}[/dim]"
        )
    if info.get("socks_port") and info.get("http_port"):
        print_exposure_warnings(
            console, listen, authenticated, int(info["socks_port"]), int(info["http_port"]), full=False
        )


def _resolve_route_plan(preset: RoutePreset) -> RoutePlan:
    if preset == RoutePreset.CUSTOM:
        from v2rm.routing.custom import load_custom_route_plan

        return load_custom_route_plan()
    return get_builtin(preset)
