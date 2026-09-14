from __future__ import annotations

import typer
from rich.console import Console

from v2rm.errors import V2rmError
from v2rm.store.state import AppStateStore

console = Console()
port_app = typer.Typer(help="Configure the local SOCKS/HTTP proxy ports.")


@port_app.command("show")
def show_ports() -> None:
    """Show the configured SOCKS/HTTP ports."""
    state = AppStateStore().load()
    console.print(f"  socks   127.0.0.1:{state.socks_port}")
    console.print(f"  http    127.0.0.1:{state.http_port}")


@port_app.command("set")
def set_ports(
    socks: int | None = typer.Option(None, "--socks", help="New local SOCKS port."),
    http: int | None = typer.Option(None, "--http", help="New local HTTP port."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Don't ask for confirmation before reconnecting."),
) -> None:
    """Change the local SOCKS/HTTP ports. Reconnects immediately if already connected."""
    if socks is None and http is None:
        console.print("[yellow]Nothing to change -- pass --socks and/or --http.[/yellow]")
        raise typer.Exit()

    for value, label in ((socks, "--socks"), (http, "--http")):
        if value is not None and not (1 <= value <= 65535):
            raise V2rmError(f"{label} must be a valid port number (1-65535), got {value}")
    if socks is not None and http is not None and socks == http:
        raise V2rmError("--socks and --http must be different ports")

    state_store = AppStateStore()
    state = state_store.load()
    if socks is not None:
        state.socks_port = socks
    if http is not None:
        state.http_port = http

    from v2rm.process import supervisor

    connected, _ = supervisor.is_connected()
    if connected and not yes and not typer.confirm("Reconnect now to apply the new ports?"):
        state_store.save(state)
        console.print("[yellow]Saved.[/yellow] Run `v2rm connect` to apply the new ports.")
        return

    state_store.save(state)
    console.print(f"[green]Ports updated[/green] -- socks {state.socks_port}, http {state.http_port}")

    if connected:
        from v2rm.cli.connect import connect_command

        connect_command(None)
