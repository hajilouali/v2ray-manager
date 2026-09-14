from __future__ import annotations

import os
import sys

from rich.console import Console

from v2rm.coredl.install import current_version
from v2rm.process import supervisor
from v2rm.store import paths
from v2rm.store.state import AppStateStore

console = Console()


def doctor_command() -> None:
    """Check the environment: platform, installed engines, connection state, ports."""
    checks: list[tuple[bool, str]] = []

    is_linux = sys.platform.startswith("linux")
    checks.append(
        (is_linux, f"Running on Linux ({sys.platform})")
        if is_linux
        else (False, f"Not running on Linux ({sys.platform}) -- v2rm targets Linux only")
    )

    for engine in ("xray", "singbox"):
        version = current_version(engine)
        checks.append(
            (True, f"{engine} installed ({version})")
            if version
            else (False, f"{engine} not installed -- run `v2rm core install {engine}`")
        )

    connected, pid = supervisor.is_connected()
    checks.append((True, f"Connected (pid {pid})" if connected else "Not connected"))

    state = AppStateStore().load()
    checks.append((True, f"SOCKS port {state.socks_port}, HTTP port {state.http_port}"))
    if state.listen_address == "127.0.0.1":
        checks.append((True, "Listening on 127.0.0.1 (localhost only)"))
    else:
        checks.append(
            (False, f"Listening on {state.listen_address} (not just localhost) -- confirm a firewall restricts who can reach it")
        )
    checks.append((True, f"Route preset: {state.route_preset.value}"))

    editor = os.environ.get("EDITOR")
    checks.append(
        (True, f"$EDITOR is set ({editor})")
        if editor
        else (False, "$EDITOR is not set -- `profile edit`/`route edit` will fall back to nano")
    )

    for name, path in (("config", paths.config_dir()), ("data", paths.data_dir()), ("state", paths.state_dir())):
        writable = os.access(path, os.W_OK) if path.exists() else True
        checks.append(
            (True, f"{name} dir writable ({path})")
            if writable
            else (False, f"{name} dir NOT writable ({path})")
        )

    for ok, message in checks:
        icon = "[green]ok[/green]  " if ok else "[yellow]warn[/yellow]"
        console.print(f"{icon} {message}")
