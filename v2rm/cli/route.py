from __future__ import annotations

import os
import subprocess

import typer
from rich.console import Console

from v2rm.models.enums import RoutePreset
from v2rm.routing.custom import load_custom_route_plan, scaffold_if_missing
from v2rm.routing.model import RoutePlan
from v2rm.routing.presets import get_builtin
from v2rm.store import paths
from v2rm.store.state import AppStateStore

console = Console()
route_app = typer.Typer(help="Manage routing rules (what bypasses the proxy).")


def _resolve_plan(preset: RoutePreset) -> RoutePlan:
    if preset == RoutePreset.CUSTOM:
        return load_custom_route_plan()
    return get_builtin(preset)


@route_app.command("show")
def show_route(
    preset: RoutePreset | None = typer.Option(
        None, "--preset", help="Preview a preset instead of the currently active one."
    ),
) -> None:
    """Show the resolved rule table for the active (or a previewed) preset."""
    target = preset or AppStateStore().load().route_preset
    plan = _resolve_plan(target)

    console.print(f"[bold]{target.value}[/bold]")
    if not plan.rules:
        console.print("  [dim](no bypass rules -- everything goes through the proxy)[/dim]")
        return

    for rule in plan.rules:
        parts = []
        if rule.domain_suffix:
            parts.append(f"domain_suffix={rule.domain_suffix}")
        if rule.domain_keyword:
            parts.append(f"domain_keyword={rule.domain_keyword}")
        if rule.geosite:
            parts.append(f"geosite={rule.geosite}")
        if rule.ip_cidr:
            parts.append(f"ip_cidr={rule.ip_cidr}")
        if rule.geoip:
            parts.append(f"geoip={rule.geoip}")
        console.print(f"  [cyan]{rule.kind}[/cyan]  {' '.join(parts)}")


@route_app.command("set")
def set_route(preset: RoutePreset = typer.Argument(..., help="global | bypass-ir | bypass-cn | custom")) -> None:
    """Switch the active routing preset. Live-switches if already connected."""
    if preset == RoutePreset.CUSTOM:
        scaffold_if_missing()

    state_store = AppStateStore()
    state = state_store.load()
    state.route_preset = preset
    state_store.save(state)
    console.print(f"[green]Route preset set to[/green] {preset.value}")

    from v2rm.process import supervisor

    connected, _ = supervisor.is_connected()
    if connected:
        from v2rm.cli.connect import connect_command

        connect_command(None)


@route_app.command("edit")
def edit_route() -> None:
    """Open $EDITOR on the custom routing rules file (created from a template on first use)."""
    scaffold_if_missing()
    editor = os.environ.get("EDITOR", "nano")
    path = paths.custom_routes_file()
    subprocess.run([editor, str(path)], check=True)

    load_custom_route_plan()  # validate immediately so mistakes surface now, not at connect time
    console.print(f"[green]Saved[/green] {path}")


@route_app.command("update-data")
def update_route_data(
    force: bool = typer.Option(False, "--force", help="Re-download even if already cached."),
) -> None:
    """Refresh the cached GeoIP/GeoSite data Xray-core needs for geosite:/geoip: rules."""
    from v2rm.routing.assets import update_xray_geodata

    changed = update_xray_geodata(force=force)
    if changed:
        console.print("[green]Updated[/green] geoip.dat and geosite.dat")
    else:
        console.print("[dim]Already up to date.[/dim]")
