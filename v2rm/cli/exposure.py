"""Shared printing of the 'this proxy is reachable beyond localhost' warnings
(`connect`, `status`, `port set`, `doctor`). Warnings only -- never blocks."""

from __future__ import annotations

from rich.console import Console
from rich.markup import escape

from v2rm.net.exposure import listen_warning, open_proxy_warning


def print_exposure_warnings(
    console: Console,
    listen: str,
    authenticated: bool,
    socks_port: int,
    http_port: int,
    full: bool = True,
) -> None:
    """Nothing for a loopback listen address. Otherwise a one-line warning, and
    when the proxy has no login also that it is open plus (if `full`) the
    firewall commands to restrict it."""
    warning = listen_warning(listen)
    if warning is None:
        return
    console.print(f"[bold yellow]Warning:[/bold yellow] {escape(warning)}")
    if authenticated:
        return
    headline, *guidance = open_proxy_warning(listen, socks_port, http_port)
    console.print(f"  [yellow]{escape(headline)}[/yellow]")
    if full:
        for line in guidance:
            console.print(f"  {escape(line)}")
    else:
        console.print("  [dim]`v2rm doctor` shows the firewall commands.[/dim]")
