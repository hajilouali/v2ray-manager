from __future__ import annotations

import os
import subprocess

import typer
from rich.console import Console

from v2rm.errors import NotConnectedError
from v2rm.process import supervisor

console = Console()
err_console = Console(stderr=True)


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

    http_url = f"http://127.0.0.1:{http_port}"
    socks_url = f"socks5h://127.0.0.1:{socks_port}"
    no_proxy = "localhost,127.0.0.1,::1"

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


def env_command(
    shell: str = typer.Option(
        "sh", "--shell", help="Output syntax: sh (default -- also works for bash/zsh) or fish."
    ),
) -> None:
    """Print proxy environment variables for one shell to opt into, e.g.
    `eval "$(v2rm env)"`. Only that shell session is affected -- nothing
    system-wide ever changes."""
    env_vars = _proxy_env_vars()
    for key, value in env_vars.items():
        if shell == "fish":
            console.print(f"set -gx {key} {value}")
        else:
            console.print(f"export {key}={value}")


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
