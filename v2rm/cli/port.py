from __future__ import annotations

import typer
from rich.console import Console

from v2rm.cli.exposure import print_exposure_warnings
from v2rm.errors import V2rmError
from v2rm.models.auth import ProxyAuth
from v2rm.net import addresses
from v2rm.net.docker import OTHER_NETWORKS_NOTE, resolve_docker_gateway
from v2rm.store.auth import AuthStore
from v2rm.store.state import AppStateStore

console = Console()
port_app = typer.Typer(help="Configure the local SOCKS/HTTP proxy ports, listen address and login.")


@port_app.command("show")
def show_ports() -> None:
    """Show the configured listen address, SOCKS/HTTP ports and whether a login is required."""
    state = AppStateStore().load()
    problem: V2rmError | None = None
    try:
        auth = AuthStore().load()
    except V2rmError as exc:  # still show everything else, and how to fix this
        auth, problem = None, exc
    console.print(f"  listen  {state.listen_address}")
    console.print(f"  socks   {state.listen_address}:{state.socks_port}")
    console.print(f"  http    {state.listen_address}:{state.http_port}")
    if problem is not None:
        console.print(f"  auth    [red]unreadable[/red] -- {problem}")
        return
    console.print(f"  auth    {f'required (user: {auth.user})' if auth else 'none'}")
    print_exposure_warnings(
        console, state.listen_address, auth is not None, state.socks_port, state.http_port, full=False
    )


def _resolve_listen(value: str) -> str:
    """Validate `--listen`, resolving the special value 'docker' to the Docker
    bridge address (and saying what it found)."""
    value = value.strip()
    if value.lower() != "docker":
        addresses.check_listen_address(value)
        return value

    gateway = resolve_docker_gateway()
    console.print(f"Docker bridge address: [bold]{gateway.address}[/bold] [dim](from {gateway.source})[/dim]")
    console.print(f"[dim]{OTHER_NETWORKS_NOTE}[/dim]")
    if not addresses.is_wildcard(gateway.address) and not addresses.local_address_exists(gateway.address):
        raise V2rmError(
            f"Docker reports its bridge gateway as {gateway.address}, but this host has no such address, "
            "so nothing can listen on it (rootless Docker and Docker Desktop keep their bridge elsewhere). "
            "Use `--listen 0.0.0.0` together with a firewall rule or `--auth`, or an address this host does have."
        )
    return gateway.address


@port_app.command("set")
def set_ports(
    socks: int | None = typer.Option(None, "--socks", help="New local SOCKS port."),
    http: int | None = typer.Option(None, "--http", help="New local HTTP port."),
    listen: str | None = typer.Option(
        None,
        "--listen",
        "-l",
        help="Address to bind to: 127.0.0.1 (default -- this host only), 0.0.0.0 (all interfaces), "
        "a specific address of this host, or 'docker' for the Docker bridge address that containers "
        "use to reach the host. Anything but 127.0.0.1 lets other things connect -- pair it with "
        "--auth and/or a firewall (`v2rm doctor` shows the commands). See the README's Docker section.",
    ),
    auth: str | None = typer.Option(
        None,
        "--auth",
        metavar="USER:PASS",
        help="Require this login on both the SOCKS and HTTP ports. Stored in a file only you can read.",
    ),
    no_auth: bool = typer.Option(False, "--no-auth", help="Stop requiring a login."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Don't ask for confirmation before reconnecting."),
) -> None:
    """Change the local SOCKS/HTTP ports, listen address and/or login. Reconnects immediately if already connected."""
    if socks is None and http is None and listen is None and auth is None and not no_auth:
        console.print("[yellow]Nothing to change -- pass --socks, --http, --listen, --auth and/or --no-auth.[/yellow]")
        raise typer.Exit()

    for value, label in ((socks, "--socks"), (http, "--http")):
        if value is not None and not (1 <= value <= 65535):
            raise V2rmError(f"{label} must be a valid port number (1-65535), got {value}")
    if socks is not None and http is not None and socks == http:
        raise V2rmError("--socks and --http must be different ports")
    if auth is not None and no_auth:
        raise V2rmError("--auth and --no-auth can't be used together")

    new_auth = ProxyAuth.parse(auth) if auth is not None else None
    new_listen = _resolve_listen(listen) if listen is not None else None

    state_store = AppStateStore()
    state = state_store.load()
    if socks is not None:
        state.socks_port = socks
    if http is not None:
        state.http_port = http
    if new_listen is not None:
        state.listen_address = new_listen

    auth_store = AuthStore()
    effective_auth = new_auth if new_auth is not None else (None if no_auth else auth_store.load())

    from v2rm.process import supervisor

    connected, _ = supervisor.is_connected()
    reconnect = connected and (yes or typer.confirm("Reconnect now to apply the changes?"))

    state_store.save(state)
    if new_auth is not None:
        auth_store.save(new_auth)
    elif no_auth:
        auth_store.clear()

    if connected and not reconnect:
        console.print("[yellow]Saved.[/yellow] Run `v2rm connect` to apply the changes.")
    else:
        console.print(
            f"[green]Updated[/green] -- listen {state.listen_address}, "
            f"socks port {state.socks_port}, http port {state.http_port}, "
            f"login {'required' if effective_auth else 'not required'}"
        )

    if reconnect:
        from v2rm.cli.connect import connect_command

        connect_command(None)  # prints the exposure warnings itself
        return
    print_exposure_warnings(
        console, state.listen_address, effective_auth is not None, state.socks_port, state.http_port
    )
