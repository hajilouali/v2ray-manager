"""Finding the address containers use to reach this host (the Docker bridge
gateway), so `--listen docker` and `env --docker` don't need it typed in."""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass

from v2rm.errors import V2rmError
from v2rm.net.addresses import parse_ip

_INSPECT_ARGS = ["docker", "network", "inspect", "bridge", "--format", "{{(index .IPAM.Config 0).Gateway}}"]
_IP_ADDR_LINE = re.compile(r"\binet\s+(\d+\.\d+\.\d+\.\d+)")

OTHER_NETWORKS_NOTE = (
    "This is the host's address on Docker's default bridge network. Containers on other networks "
    "(docker compose creates one per project) can get a different gateway, e.g. 172.18.0.1, and your "
    "firewall has to allow their subnet as well. If one can't connect, check "
    "`docker network inspect <network>`; `--listen 0.0.0.0` (with a firewall rule or `--auth`) "
    "covers every network at once."
)


@dataclass(frozen=True)
class DockerGateway:
    address: str
    source: str  # how it was found, for telling the user


def _run(runner: Callable[..., subprocess.CompletedProcess], args: list[str]) -> str | None:
    try:
        proc = runner(args, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout or ""


def parse_gateway_output(text: str) -> str | None:
    """The output of `docker network inspect ... --format '{{...Gateway}}'`: a
    single IP address, or nothing usable."""
    candidate = text.strip()
    return candidate if parse_ip(candidate) is not None else None


def parse_interface_address(ip_output: str) -> str | None:
    """The first IPv4 address in `ip -4 -o addr show dev docker0` output."""
    match = _IP_ADDR_LINE.search(ip_output)
    return match.group(1) if match and parse_ip(match.group(1)) is not None else None


def resolve_docker_gateway(runner: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> DockerGateway:
    """The bridge gateway: first `docker network inspect bridge` (authoritative,
    but needs the docker CLI and permission to use it), then the address of the
    `docker0` interface (works without either)."""
    inspected = _run(runner, _INSPECT_ARGS)
    address = parse_gateway_output(inspected) if inspected is not None else None
    if address:
        return DockerGateway(address, "`docker network inspect bridge`")

    interface = _run(runner, ["ip", "-4", "-o", "addr", "show", "dev", "docker0"])
    address = parse_interface_address(interface) if interface is not None else None
    if address:
        return DockerGateway(address, "the docker0 interface")

    raise V2rmError(
        "Couldn't find the Docker bridge address: `docker network inspect bridge` failed (is Docker "
        "installed and running, and are you allowed to use it?) and there is no docker0 interface. "
        "Pass the address yourself, e.g. `v2rm port set --listen 172.17.0.1`."
    )
