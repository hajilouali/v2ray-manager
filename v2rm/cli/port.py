from __future__ import annotations

import ipaddress

import typer
from rich.console import Console

from v2rm.errors import V2rmError
from v2rm.store.state import AppStateStore

console = Console()
port_app = typer.Typer(help="Configure the local SOCKS/HTTP proxy ports and listen address.")


@port_app.command("show")
def show_ports() -> None:
    """Show the configured listen address and SOCKS/HTTP ports."""
    state = AppStateStore().load()
    console.print(f"  listen  {state.listen_address}")
    console.print(f"  socks   {state.listen_address}:{state.socks_port}")
    console.print(f"  http    {state.listen_address}:{state.http_port}")


@port_app.command("set")
def set_ports(
    socks: int | None = typer.Option(None, "--socks", help="New local SOCKS port."),
    http: int | None = typer.Option(None, "--http", help="New local HTTP port."),
    listen: str | None = typer.Option(
        None,
        "--listen",
        "-l",
        help="Address to bind to. Default 127.0.0.1 (this host only, nothing else can reach it). "
        "Use 0.0.0.0 or a specific interface IP (e.g. a Docker bridge gateway) to let something "
        "else reach it -- pair this with a firewall rule restricting who can, since the proxy has "
        "no authentication of its own. See the README's Docker section.",
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Don't ask for confirmation before reconnecting."),
) -> None:
    """Change the local SOCKS/HTTP ports and/or listen address. Reconnects immediately if already connected."""
    if socks is None and http is None and listen is None:
        console.print("[yellow]Nothing to change -- pass --socks, --http, and/or --listen.[/yellow]")
        raise typer.Exit()

    for value, label in ((socks, "--socks"), (http, "--http")):
        if value is not None and not (1 <= value <= 65535):
            raise V2rmError(f"{label} must be a valid port number (1-65535), got {value}")
    if socks is not None and http is not None and socks == http:
        raise V2rmError("--socks and --http must be different ports")

    if listen is not None:
        try:
            ipaddress.ip_address(listen)
        except ValueError as exc:
            raise V2rmError(f"--listen must be a valid IP address, got '{listen}'") from exc

    state_store = AppStateStore()
    state = state_store.load()
    if socks is not None:
        state.socks_port = socks
    if http is not None:
        state.http_port = http
    if listen is not None:
        state.listen_address = listen

    if listen is not None and listen != "127.0.0.1":
        console.print(
            "[bold yellow]Warning:[/bold yellow] the local proxy has no authentication of its own -- "
            f"anything that can reach {listen}:<port> can tunnel through it. Make sure a firewall "
            "restricts access to only who should have it."
        )

    from v2rm.process import supervisor

    connected, _ = supervisor.is_connected()
    if connected and not yes and not typer.confirm("Reconnect now to apply the changes?"):
        state_store.save(state)
        console.print("[yellow]Saved.[/yellow] Run `v2rm connect` to apply the changes.")
        return

    state_store.save(state)
    console.print(
        f"[green]Updated[/green] -- listen {state.listen_address}, "
        f"socks port {state.socks_port}, http port {state.http_port}"
    )

    if connected:
        from v2rm.cli.connect import connect_command

        connect_command(None)
