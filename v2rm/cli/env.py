from __future__ import annotations

import os
import subprocess

import typer
from rich.console import Console

from v2rm.errors import NotConnectedError, V2rmError
from v2rm.models.auth import ProxyAuth
from v2rm.net.addresses import is_loopback, is_wildcard, parse_ip
from v2rm.net.docker import resolve_docker_gateway
from v2rm.process import supervisor
from v2rm.store.auth import AuthStore
from v2rm.store.state import AppStateStore

console = Console()
err_console = Console(stderr=True)

_LOCAL_NO_PROXY = ("localhost", "127.0.0.1", "::1")


def url_host(address: str) -> str:
    """The host part of a URL: IPv6 literals need brackets."""
    return f"[{address}]" if ":" in address and parse_ip(address) is not None else address


def env_vars_for(
    address: str, socks_port: int, http_port: int, auth: ProxyAuth | None, no_proxy_extra: tuple[str, ...] = ()
) -> dict[str, str]:
    """The proxy environment variables for a client that reaches the proxy at
    `address`. The login, if there is one, is percent-encoded into the URLs."""
    userinfo = f"{auth.userinfo()}@" if auth else ""
    host = url_host(address)
    http_url = f"http://{userinfo}{host}:{http_port}"
    socks_url = f"socks5h://{userinfo}{host}:{socks_port}"
    no_proxy = ",".join(dict.fromkeys((*_LOCAL_NO_PROXY, *no_proxy_extra)))

    return {
        "http_proxy": http_url,
        "https_proxy": http_url,
        "all_proxy": socks_url,
        "HTTP_PROXY": http_url,
        "HTTPS_PROXY": http_url,
        "ALL_PROXY": socks_url,
        "no_proxy": no_proxy,
        "NO_PROXY": no_proxy,
    }


def _proxy_env_vars() -> dict[str, str]:
    info = supervisor.status()
    if not info.get("connected"):
        raise NotConnectedError("Not connected. Run `v2rm connect <profile>` first.")

    socks_port = info.get("socks_port")
    http_port = info.get("http_port")
    if socks_port is None or http_port is None:
        raise NotConnectedError(
            "Connected, but port info is missing (corrupted state) -- "
            "try `v2rm disconnect` then `v2rm connect` again."
        )

    # The address this host should connect to: the bound one, which for a
    # specific listen address (a Docker bridge IP, say) is not 127.0.0.1.
    address = supervisor.client_address(info.get("listen_address", "127.0.0.1"))
    auth = AuthStore().load() if info.get("authenticated") else None
    extra = () if address == "127.0.0.1" else (address,)
    return env_vars_for(address, int(socks_port), int(http_port), auth, extra)


def _container_warnings(listen: str, address: str) -> list[str]:
    """Reasons a container using `address` would not actually reach the proxy."""
    if is_loopback(listen):
        return [
            f"v2rm listens on {listen}, which containers can't reach. Run `v2rm port set --listen docker` "
            "(or `--listen 0.0.0.0` together with a firewall rule or `--auth`) first."
        ]
    if not is_wildcard(listen) and parse_ip(address) is not None and address != listen:
        return [
            f"v2rm listens on {listen}, not on {address}, so a container using this block can't connect. "
            "Run `v2rm port set --listen docker` (or `--listen 0.0.0.0`)."
        ]
    return []


def _container_block(host: str | None, use_docker: bool) -> None:
    """Print KEY=value lines for a container (an env file, `docker run --env-file`,
    compose `env_file:`). Comments and the block go to stdout so it can be
    redirected to a file; problems go to stderr."""
    if host is not None and use_docker:
        raise V2rmError("Use either --host or --docker, not both")
    if use_docker:
        gateway = resolve_docker_gateway()
        address = gateway.address
        err_console.print(f"Docker bridge address: {address} (from {gateway.source})", markup=False, highlight=False)
    else:
        address = (host or "").strip()
        if not address:
            raise V2rmError("--host needs an address or host name, e.g. --host 172.17.0.1 or --host host.docker.internal")

    state = AppStateStore().load()
    auth = AuthStore().load()
    for warning in _container_warnings(state.listen_address, address):
        err_console.print(f"Warning: {warning}", markup=False, highlight=False)

    env = env_vars_for(address, state.socks_port, state.http_port, auth, (address,))
    typer.echo("# v2rm proxy settings for a container (use as an env file, e.g. `docker run --env-file proxy.env`).")
    typer.echo(f"# The container must be able to reach {address}. To use a name instead, start it with")
    typer.echo("#   docker run --add-host=host.docker.internal:host-gateway ...")
    typer.echo('#   (compose: extra_hosts: ["host.docker.internal:host-gateway"])')
    typer.echo("# and generate this block with `v2rm env --host host.docker.internal`.")
    if auth is not None:
        typer.echo("# It contains the proxy login -- keep the file private.")
    for key, value in env.items():
        typer.echo(f"{key}={value}")


def env_command(
    shell: str = typer.Option(
        "sh", "--shell", help="Output syntax: sh (default -- also works for bash/zsh) or fish."
    ),
    host: str | None = typer.Option(
        None,
        "--host",
        metavar="ADDR",
        help="Instead of export lines for this shell, print VAR=value lines for a container that "
        "reaches the proxy at ADDR (an IP, or a name like host.docker.internal).",
    ),
    docker: bool = typer.Option(
        False, "--docker", help="Like --host, using the Docker bridge address (the host as containers see it)."
    ),
) -> None:
    """Print proxy environment variables for one shell to opt into, e.g.
    `eval "$(v2rm env)"`. Only that shell session is affected -- nothing
    system-wide ever changes. With --host/--docker, print a block for a
    container instead."""
    if host is not None or docker:
        _container_block(host, docker)
        return

    env_vars = _proxy_env_vars()
    for key, value in env_vars.items():
        # typer.echo, not rich: rich wraps long lines, which would break `eval`.
        typer.echo(f"set -gx {key} {value}" if shell == "fish" else f"export {key}={value}")


def exec_command(
    command: list[str] = typer.Argument(
        ..., help="Command (and its own arguments) to run with the proxy env vars set."
    ),
) -> None:
    """Run a single command with the proxy environment variables injected
    into that command's own environment only -- e.g. `v2rm exec -- curl
    https://example.com`. Nothing else on the system is touched."""
    env_vars = _proxy_env_vars()
    env = dict(os.environ)
    env.update(env_vars)

    result = subprocess.run(command, env=env)
    raise typer.Exit(code=result.returncode)
