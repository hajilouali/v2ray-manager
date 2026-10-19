"""Listen-address helpers: what an address means, and whether this host has it."""

from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
from collections.abc import Callable

from v2rm.errors import V2rmError

WILDCARDS = frozenset({"0.0.0.0", "::", ""})

_IP_ADDR_LINE = re.compile(r"\binet6?\s+([0-9a-fA-F:.]+)(?:/\d+)?")


def parse_ip(address: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(address.strip())
    except ValueError:
        return None


def is_wildcard(address: str) -> bool:
    return address.strip() in WILDCARDS


def is_loopback(address: str) -> bool:
    ip = parse_ip(address)
    return ip is not None and ip.is_loopback


def reaches_beyond_localhost(address: str) -> bool:
    """True when a proxy bound here can be reached by something other than
    processes on this host's loopback: a wildcard or any specific non-loopback
    address."""
    return not is_loopback(address)


def local_address_exists(address: str) -> bool:
    """Whether this host could bind `address` -- i.e. it is one of its own
    addresses. A bind probe on an ephemeral port: nothing is left listening,
    and it needs no external tools. (If the kernel allows non-local binds,
    `net.ipv4.ip_nonlocal_bind=1`, every address looks present; that is the
    setting's documented meaning.)"""
    ip = parse_ip(address)
    if ip is None:
        return False
    if is_wildcard(address):
        return True
    family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as probe:
            probe.bind((str(ip), 0))
    except OSError:
        return False
    return True


def local_addresses(runner: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> list[str] | None:
    """This host's interface addresses via `ip -o addr`, or None if that can't
    be run. Only used to make an error message more helpful."""
    try:
        proc = runner(["ip", "-o", "addr", "show"], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    found: list[str] = []
    for line in (proc.stdout or "").splitlines():
        match = _IP_ADDR_LINE.search(line)
        if match and parse_ip(match.group(1)) is not None and match.group(1) not in found:
            found.append(match.group(1))
    return found or None


def _missing_address_message(address: str, lister: Callable[[], list[str] | None] | None) -> str:
    message = f"This host has no address {address}, so nothing can listen on it."
    known = (lister or local_addresses)()
    if known:
        message += f" Its addresses: {', '.join(known)}."
    return message


def check_listen_address(
    address: str,
    exists: Callable[[str], bool] | None = None,
    lister: Callable[[], list[str] | None] | None = None,
) -> None:
    """Raise V2rmError if `address` is not an IP address, or is a specific
    address this host doesn't have (so no engine could ever bind to it) --
    used by `port set --listen`. Wildcards always pass. This deliberately says
    nothing about whether listening there is a good idea: that's the user's
    decision (see `v2rm.net.exposure` for the warnings).

    `exists`/`lister` default to the real probes, looked up at call time."""
    if parse_ip(address) is None:
        raise V2rmError(f"--listen must be a valid IP address (or 'docker'), got '{address}'")
    if is_wildcard(address) or (exists or local_address_exists)(address):
        return
    raise V2rmError(
        _missing_address_message(address, lister)
        + " A Docker bridge address only exists while Docker is running -- "
        "`v2rm port set --listen docker` looks it up."
    )


def ensure_listen_address_available(
    address: str,
    exists: Callable[[str], bool] | None = None,
    lister: Callable[[], list[str] | None] | None = None,
) -> None:
    """The same check at `connect` time, for a saved address that has since
    disappeared (Docker stopped, an interface went down): without it the
    engine would just exit with a bind error."""
    if is_wildcard(address) or parse_ip(address) is None or (exists or local_address_exists)(address):
        return
    raise V2rmError(
        _missing_address_message(address, lister)
        + " (A Docker bridge address only exists while Docker is running.) Start whatever provides it, "
        "or choose another address with `v2rm port set --listen ...`."
    )
