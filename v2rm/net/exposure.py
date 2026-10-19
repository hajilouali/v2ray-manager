"""Warnings for a proxy that listens beyond localhost.

These only ever *inform*: where the proxy listens is the user's decision, and
v2rm never refuses or changes it because of what's printed here.
"""

from __future__ import annotations

import ipaddress

from v2rm.net.addresses import is_loopback, is_wildcard, parse_ip

# Docker's default address pools (the bridge is 172.17.0.0/16, user-defined
# networks are carved out of 172.18-172.31 and then 192.168.0.0/16).
DOCKER_SUBNETS = "172.16.0.0/12"
_PLACEHOLDER_SOURCE = "<trusted-subnet>"


def listen_warning(listen: str) -> str | None:
    """One line, or None when the proxy is only reachable from this host."""
    if is_loopback(listen):
        return None
    if is_wildcard(listen):
        return "Listening on all interfaces (0.0.0.0), not just localhost -- other machines and containers can reach it."
    return f"Listening on {listen}, not just localhost -- anything that can reach that address can connect."


def suggested_source(listen: str) -> str:
    """The source range to put in a firewall rule: Docker's private ranges when
    the listen address is a wildcard or inside them, otherwise a placeholder the
    user has to fill in (v2rm can't know their LAN)."""
    ip = parse_ip(listen)
    if is_wildcard(listen):
        return DOCKER_SUBNETS
    if ip is not None and ip.version == 4 and ip in ipaddress.ip_network(DOCKER_SUBNETS):
        return DOCKER_SUBNETS
    return _PLACEHOLDER_SOURCE


def ufw_commands(listen: str, socks_port: int, http_port: int) -> list[str]:
    ports = f"{socks_port},{http_port}"
    return [
        f"sudo ufw allow from {suggested_source(listen)} to any port {ports} proto tcp",
        f"sudo ufw deny {ports}/tcp",
    ]


def open_proxy_warning(listen: str, socks_port: int, http_port: int) -> list[str]:
    """For a proxy with no authentication that listens beyond localhost: the
    warning plus the firewall commands to restrict it. Empty for loopback."""
    if is_loopback(listen):
        return []
    where = "every interface" if is_wildcard(listen) else listen
    allow, deny = ufw_commands(listen, socks_port, http_port)
    return [
        f"This proxy has no authentication: anything that can reach {where} on ports "
        f"{socks_port}/{http_port} can use your connection.",
        "Restrict it with a firewall, for example (ufw):",
        f"  {allow}",
        f"  {deny}   # only needed if your default policy allows incoming traffic",
        "or require a login instead: `v2rm port set --auth USER:PASS`.",
    ]
