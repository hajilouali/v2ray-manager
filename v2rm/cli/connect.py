from __future__ import annotations

import typer
from rich.console import Console

from v2rm.engines import engine_for_protocol
from v2rm.errors import V2rmError
from v2rm.models.enums import RoutePreset
from v2rm.process import supervisor
from v2rm.routing.model import RoutePlan
from v2rm.routing.presets import get_builtin
from v2rm.store.profiles import ProfileStore
from v2rm.store.state import AppStateStore

console = Console()


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
        state.active_profile_id = profile.id
    elif state.active_profile_id:
        profile = profile_store.resolve(state.active_profile_id)
    else:
        raise V2rmError(
            "No active profile. Run `v2rm connect <profile>` or `v2rm profile use <profile>` first."
        )

    if state.active_engine is None:
        state.active_engine = engine_for_protocol(profile.protocol)

    route_plan = _resolve_route_plan(state.route_preset)

    supervisor.connect(
        profile,
        state.active_engine,
        route_plan,
        state.socks_port,
        state.http_port,
        listen_address=state.listen_address,
    )
    state_store.save(state)

    console.print(
        f"[green]Connected[/green] via {state.active_engine.value} -> {profile.name} "
        f"[dim](socks {state.listen_address}:{state.socks_port}, http {state.listen_address}:{state.http_port})[/dim]"
    )


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
    console.print("[bold green]Connected[/bold green]")
    console.print(f"  profile   {info.get('profile_name', '?')}")
    console.print(f"  engine    {info.get('engine', '?')}")
    console.print(f"  pid       {info.get('pid')}")
    console.print(f"  socks     {listen}:{info.get('socks_port')}")
    console.print(f"  http      {listen}:{info.get('http_port')}")
    if listen != "127.0.0.1":
        console.print(
            "  [yellow]note:[/yellow] listening beyond localhost -- make sure a firewall "
            "restricts who can reach these ports"
        )


def _resolve_route_plan(preset: RoutePreset) -> RoutePlan:
    if preset == RoutePreset.CUSTOM:
        from v2rm.routing.custom import load_custom_route_plan

        return load_custom_route_plan()
    return get_builtin(preset)
