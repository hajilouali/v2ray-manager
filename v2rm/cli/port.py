from __future__ import annotations

import typer
from rich.console import Console
from rich.markup import escape

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
    if auth is None:
        console.print("  auth    none [dim](to require one: v2rm port set --user NAME)[/dim]")
    else:
        console.print(f"  auth    required (user: {escape(auth.user)})")
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


def _check_ports(socks: int | None, http: int | None) -> None:
    for value, label in ((socks, "--socks"), (http, "--http")):
        if value is not None and not (1 <= value <= 65535):
            raise V2rmError(f"{label} must be a valid port number (1-65535), got {value}")
    if socks is not None and http is not None and socks == http:
        raise V2rmError("--socks and --http must be different ports")


def _ask_password(user: str) -> str:
    """Ask for `user`'s password at a hidden prompt (twice), so it never lands in the shell history or in `ps`."""
    try:
        return typer.prompt(f"Password for {user}", hide_input=True, confirmation_prompt=True)
    except typer.Abort:  # nothing to ask on (the input ran out), or Ctrl-C
        raise V2rmError(
            "No password was given, so nothing was changed. (With no terminal to ask on, pass --password PASS.)"
        ) from None


def _resolve_login(user: str | None, password: str | None, remove: bool) -> ProxyAuth | None:
    """The login to save, or None when this call leaves the login alone (or removes it)."""
    if remove or (user is None and password is None):
        return None
    if user is None:  # only a password: it replaces the one of the login already there
        current = AuthStore().load()
        if current is None:
            raise V2rmError("--password changes the password of the current login, and there is none yet -- add --user NAME.")
        user = current.user
    ProxyAuth.check_user(user)  # before asking for a password that would be thrown away
    if password is None:
        password = _ask_password(user)
    return ProxyAuth.build(user, password)


def apply_settings(
    *,
    socks: int | None,
    http: int | None,
    listen: str | None,
    user: str | None,
    password: str | None,
    no_auth: bool,
    yes: bool,
) -> None:
    """Save whichever of the ports, listen address and login are given (None = leave it), then
    reconnect if connected. `v2rm port set` and the menu both come through here. A user name without a
    password asks for the password."""
    _check_ports(socks, http)
    state_store = AppStateStore()
    state = state_store.load()
    if socks is not None:
        state.socks_port = socks
    if http is not None:
        state.http_port = http
    if state.socks_port == state.http_port:  # one of them was left alone and the other moved onto it
        raise V2rmError(f"The SOCKS and HTTP ports can't both be {state.socks_port}")

    new_auth = _resolve_login(user, password, no_auth)
    if listen is not None:
        state.listen_address = _resolve_listen(listen)

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
        login = f"required (user: {escape(effective_auth.user)})" if effective_auth else "not required"
        console.print(
            f"[green]Updated[/green] -- listen {state.listen_address}, "
            f"socks port {state.socks_port}, http port {state.http_port}, login {login}"
        )
    if new_auth is not None:
        console.print("[dim]The login covers both ports. `v2rm env` prints proxy URLs with it filled in.[/dim]")

    if reconnect:
        from v2rm.cli.connect import connect_command

        connect_command(None)  # prints the exposure warnings itself
        return
    print_exposure_warnings(
        console, state.listen_address, effective_auth is not None, state.socks_port, state.http_port
    )


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
        "a login and/or a firewall (`v2rm doctor` shows the commands). See the README's Docker section.",
    ),
    user: str | None = typer.Option(
        None,
        "--user",
        metavar="NAME",
        help="Require this user name (with a password) on both the SOCKS and HTTP ports. "
        "Without --password you are asked for the password at a hidden prompt.",
    ),
    password: str | None = typer.Option(
        None,
        "--password",
        metavar="PASS",
        help="The password for --user. Prefer leaving it out and typing it at the hidden prompt: a value here "
        "stays in your shell history and shows up in `ps`. On its own it changes the current login's password.",
    ),
    auth: str | None = typer.Option(
        None,
        "--auth",
        metavar="USER:PASS",
        help="--user and --password in one piece. Stored in a file only you can read.",
    ),
    no_auth: bool = typer.Option(False, "--no-auth", help="Stop requiring a login: no user name or password."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Don't ask for confirmation before reconnecting."),
) -> None:
    """Change the local SOCKS/HTTP ports, listen address and/or login (one user name and password for both
    ports, or none). Reconnects immediately if already connected."""
    if no_auth and (auth is not None or user is not None or password is not None):
        raise V2rmError("--no-auth can't be used together with --auth, --user or --password")
    if auth is not None and (user is not None or password is not None):
        raise V2rmError("--auth can't be used together with --user or --password (it already carries both)")
    if auth is not None:
        parsed = ProxyAuth.parse(auth)
        user, password = parsed.user, parsed.password

    if socks is None and http is None and listen is None and user is None and password is None and not no_auth:
        console.print(
            "[yellow]Nothing to change -- pass --socks, --http, --listen, --user/--password (or --auth) "
            "and/or --no-auth.[/yellow]"
        )
        raise typer.Exit()
    apply_settings(socks=socks, http=http, listen=listen, user=user, password=password, no_auth=no_auth, yes=yes)
