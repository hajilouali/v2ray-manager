"""Aether profiles: validating their settings and building them from individual fields.

Aether is forgiving to a fault: a routing rule it cannot parse, an exit-country list it cannot
read, are silently dropped -- which for a `block` rule or an `exit_loc` restriction means the
protection the user asked for is quietly off. So v2rm checks every field up front, with
Aether's own grammar, and refuses what Aether would swallow.
"""

from __future__ import annotations

import ipaddress
import re
from typing import NoReturn

from v2rm.errors import ProfileValidationError
from v2rm.models.aether import (
    IP_VERSIONS,
    LOG_LEVELS,
    MASQUE_MODES,
    NOIZE_PROFILES,
    PERF_PROFILES,
    SCAN_MODES,
    TRANSPORTS,
    TWO_HOP_MODES,
    UDP_ONLY_MODES,
    AetherMode,
    AetherSettings,
)
from v2rm.models.enums import Protocol
from v2rm.models.profile import Profile
from v2rm.net.proxy_url import parse_proxy_url

# Environment variables v2rm sets itself; letting the `env` escape hatch override them would
# break the guarantees v2rm makes (where it listens, where its state lives, what it dials through).
OWNED_ENV = frozenset(
    {
        "AETHER_SOCKS",
        "AETHER_HTTP_PROXY",
        "AETHER_UPSTREAM",
        "AETHER_CONFIG",
        "AETHER_WG_CONFIG",
        "AETHER_MASQUE_CONFIG",
        "AETHER_REGISTER",
    }
)
_ENV_NAME = re.compile(r"^AETHER_[A-Z0-9_]+$")

_FRAGMENT = re.compile(r"^(\d+)(?:-(\d+))?$")
_BASE64 = re.compile(r"^[A-Za-z0-9+/_-]+={0,2}$")
_COUNTRIES = re.compile(r"^!?[A-Za-z]{2}(,[A-Za-z]{2})*$")
_MARK = re.compile(r"^(0[xX][0-9a-fA-F]+|\d+)$")
_TLS_LIST = re.compile(r"^[A-Za-z0-9:!+_.@=\-]+$")
_ECH_DNS = re.compile(r"^(udp|tcp|https)://\S+$")
_ROUTE_KINDS = frozenset(
    {"domain", "suffix", "full", "exact", "keyword", "regexp", "regex", "ip", "cidr", "port", "geoip", "geosite"}
)
_PYTHON_ONLY_REGEX = re.compile(r"\(\?(=|!|<=|<!)|\\[1-9]")
DEFAULT_WG_PORT = 2408


def valid_domain(name: str) -> bool:
    """Aether's own rule: labels of letters, digits, '-' and '_' (1-63 bytes each), 253 in all,
    one trailing dot allowed."""
    name = name[:-1] if name.endswith(".") else name
    if not name or len(name) > 253:
        return False
    return all(
        label and len(label) <= 63 and re.fullmatch(r"[A-Za-z0-9_-]+", label) for label in name.split(".")
    )


def parse_endpoint(text: str, what: str = "endpoint") -> str:
    """`ip:port` (an IPv6 address in brackets), normalised. The port is required -- which port
    gets through is exactly what differs between networks, so Aether assumes none."""
    value = (text or "").strip()
    host, sep, port = value.rpartition(":")
    if not sep:
        _bad_endpoint(value, what, portless=_is_ip(value.strip("[]")))
    ip_text = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        # A bare IPv6 address, with no brackets and no port, lands here too.
        _bad_endpoint(value, what, portless=_is_ip(value) or _is_ip(value.strip("[]")))
    if ":" in host and not host.startswith("["):
        _bad_endpoint(value, what)
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ProfileValidationError(f"{what}: '{value}' has an invalid port; it must be 1-65535")
    return f"[{ip}]:{port}" if ip.version == 6 else f"{ip}:{port}"


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _bad_endpoint(value: str, what: str, portless: bool = False) -> NoReturn:
    example = "162.159.192.1:2408"
    if portless:
        raise ProfileValidationError(
            f"{what}: '{value}' carries no port, and the port is required; write it out, as in {example}"
        )
    raise ProfileValidationError(
        f"{what}: '{value}' is not an endpoint; write an address and a port together, such as {example}"
    )


def endpoint_ip(endpoint: str) -> str:
    host = endpoint.rpartition(":")[0]
    return host[1:-1] if host.startswith("[") else host


def parse_route_entry(entry: str) -> tuple[str, str]:
    """Validate one routing rule the way Aether reads it and return (kind, value).

    Kinds: domain (a name and every subdomain), full, keyword, regexp, ip (a network or bare
    address), port (a port or a range), private (LAN, loopback and CGNAT space)."""
    text = entry.strip()
    if not text:
        raise ProfileValidationError("An empty routing rule was given")
    if any(ch in text for ch in ",;\n\r"):
        raise ProfileValidationError(
            f"Routing rule '{text}' contains a comma, semicolon or line break, which Aether reads as a "
            "separator between rules, so the rule would be cut in two"
        )
    if text.startswith("#"):
        raise ProfileValidationError(f"Routing rule '{text}' starts with '#', which Aether reads as a comment")

    # Aether takes what stands before the first ':' for the rule type, unless that part looks
    # like an address or a network (it has a '.' or a '/' in it). An IPv6 address has neither, so
    # written bare it is cut at its first ':' and turned into a rule nobody meant.
    head, colon, tail = text.partition(":")
    typed = bool(colon) and "." not in head and "/" not in head
    kind = head.strip().lower() if typed else ""
    value = tail.strip() if typed else text

    if typed and kind not in _ROUTE_KINDS and _network(text):
        raise ProfileValidationError(
            f"Routing rule '{text}': write an IPv6 address or network with the ip: prefix (ip:{text}); "
            "without it Aether reads the part before the first ':' as a rule type and misreads the rule"
        )

    if kind in ("domain", "suffix") or kind == "":
        if kind == "" and value.lower() == "private":
            return "private", ""
        if kind == "":
            net = _network(value)
            if net:
                return "ip", net
        name = value.lstrip("*").strip(".").lower()
        if typed and not kind:
            raise ProfileValidationError(f"Routing rule '{text}' starts with ':', which is not a rule")
        if not name or not valid_domain(name):
            raise ProfileValidationError(
                f"Routing rule '{text}' is not a domain name, address, network or known rule type "
                "(domain:, full:, keyword:, regexp:, ip:, port:, private)"
            )
        return "domain", name
    if kind in ("full", "exact"):
        name = value.lstrip("*").strip(".").lower()
        if not name or not valid_domain(name):
            raise ProfileValidationError(f"Routing rule '{text}' needs a domain name after 'full:'")
        return "full", name
    if kind == "keyword":
        if not value:
            raise ProfileValidationError(f"Routing rule '{text}' needs a word after 'keyword:'")
        return "keyword", value.lower()
    if kind in ("regexp", "regex"):
        if not value:
            raise ProfileValidationError(f"Routing rule '{text}' needs a pattern after 'regexp:'")
        try:
            re.compile(value)
        except re.error as exc:
            raise ProfileValidationError(f"Routing rule '{text}' is not a valid regular expression ({exc})") from exc
        if _PYTHON_ONLY_REGEX.search(value):
            raise ProfileValidationError(
                f"Routing rule '{text}' uses lookaround or a back-reference, which Aether's regular "
                "expressions (Rust syntax) do not support; Aether would silently drop the rule"
            )
        return "regexp", value
    if kind in ("ip", "cidr"):
        net = _network(value)
        if not net:
            raise ProfileValidationError(f"Routing rule '{text}' is not an IP address or network (such as 10.0.0.0/8)")
        return "ip", net
    if kind == "port":
        low, _, high = value.partition("-")
        try:
            lo, hi = int(low), int(high or low)
        except ValueError:
            raise ProfileValidationError(f"Routing rule '{text}' needs a port or a range, like port:25 or port:3000-3010") from None
        if not (0 < lo <= 65535 and 0 < hi <= 65535):
            raise ProfileValidationError(f"Routing rule '{text}' has a port outside 1-65535")
        return "port", f"{min(lo, hi)}-{max(lo, hi)}" if hi != lo else str(lo)
    if kind in ("geoip", "geosite") and value.lower() == "private":
        return "private", ""
    if kind in ("geoip", "geosite"):
        raise ProfileValidationError(
            f"Routing rule '{text}': Aether has no geo databases, only 'private' works with '{kind}:'. "
            "Use domain:, ip: or port: rules, or put an Xray front in charge of geo rules with a route preset."
        )
    raise ProfileValidationError(
        f"Routing rule '{text}' has an unknown type '{kind}:' (use domain:, full:, keyword:, regexp:, ip:, port: or private)"
    )


def _network(value: str) -> str:
    try:
        return str(ipaddress.ip_network(value.strip(), strict=False))
    except ValueError:
        return ""


def _choice(value: str, allowed: tuple[str, ...], what: str) -> None:
    if value and value.lower() not in allowed:
        raise ProfileValidationError(f"{what} must be one of {', '.join(allowed)}, not '{value}'")


def _positive(value: int | None, what: str) -> None:
    if value is not None and value < 1:
        raise ProfileValidationError(f"{what} must be a positive number of seconds, not {value}")


def _fragment_range(value: str, what: str, minimum: int) -> None:
    if not value:
        return
    match = _FRAGMENT.match(value.strip())
    if not match:
        raise ProfileValidationError(f"{what} must be a number or a range like 8-16, not '{value}'")
    low = int(match.group(1))
    high = int(match.group(2) or low)
    if low < minimum or high < low:
        raise ProfileValidationError(f"{what} '{value}' is not a valid range (smallest first, at least {minimum})")


def validate_settings(settings: AetherSettings) -> None:
    """Raise ProfileValidationError for settings Aether would refuse, or -- worse -- quietly
    ignore. Checks each value, then how they fit the mode."""
    mode = settings.mode

    _choice(settings.transport, TRANSPORTS, "transport")
    _choice(settings.scan, SCAN_MODES, "scan")
    _choice(settings.ip, IP_VERSIONS, "ip")
    _choice(settings.noize, NOIZE_PROFILES, "noize")
    _choice(settings.perf, PERF_PROFILES, "perf")
    _choice(settings.log_level, LOG_LEVELS, "log level")

    if settings.transport and mode in UDP_ONLY_MODES and settings.transport.lower() == "h2":
        raise ProfileValidationError(
            f"{mode.value} is UDP all the way to Cloudflare, so it has no HTTP/2 carrier. "
            "HTTP/2 (TCP) works with the masque, gool and mim modes."
        )
    if settings.h2_peer and mode not in MASQUE_MODES:
        raise ProfileValidationError(f"h2 peer only applies to the masque, gool and mim modes, not {mode.value}")

    # Gateways by hand.
    outer = parse_endpoint(settings.outer, "outer gateway") if settings.outer else ""
    inner = parse_endpoint(settings.inner, "inner gateway") if settings.inner else ""
    if settings.h2_peer:
        parse_endpoint(settings.h2_peer, "h2 peer")
    if inner and mode not in TWO_HOP_MODES:
        raise ProfileValidationError(
            f"{mode.value} has a single hop, so an inner gateway makes no sense; "
            "it only applies to the gool, gool-classic and mim modes"
        )
    if outer and inner and mode != AetherMode.GOOL and endpoint_ip(outer) == endpoint_ip(inner):
        raise ProfileValidationError(
            f"The two hops need separate edges, but both point at {endpoint_ip(outer)}"
        )

    # Obfuscation and fragmentation.
    _fragment_range(settings.fragment_size, "fragment size", 1)
    _fragment_range(settings.fragment_delay, "fragment delay", 0)
    if (settings.fragment_size or settings.fragment_delay) and not settings.fragment:
        raise ProfileValidationError("fragment size/delay only take effect with fragmentation turned on")

    # TLS.
    if settings.sni and (_is_ip(settings.sni.strip("[]")) or not valid_domain(settings.sni.strip())):
        raise ProfileValidationError(f"SNI '{settings.sni}' is no domain name (an IP address can't be a server name)")
    if settings.ech and settings.ech.lower() != "auto" and not _BASE64.match(settings.ech):
        raise ProfileValidationError("ech must be 'auto' or an ECH config list in base64")
    if settings.ech_dns and not _ECH_DNS.match(settings.ech_dns):
        raise ProfileValidationError("ech dns must be a udp://, tcp:// or https:// URL")
    if settings.ech_domain and not valid_domain(settings.ech_domain):
        raise ProfileValidationError(f"ech domain '{settings.ech_domain}' is no domain name")
    if settings.tls_ciphers and not _TLS_LIST.match(settings.tls_ciphers):
        raise ProfileValidationError("tls ciphers: use cipher suite names separated by ':'")
    if settings.tls_groups and not _TLS_LIST.match(settings.tls_groups):
        raise ProfileValidationError("tls groups: use group names separated by ':'")

    # Timers.
    _positive(settings.reconnect_secs, "reconnect delay")
    _positive(settings.startup_secs, "startup timeout")
    _positive(settings.validate_secs, "validation timeout")
    _positive(settings.keepalive, "keepalive")
    _positive(settings.exit_loc_secs, "exit location recheck interval")
    _positive(settings.route_sniff_ms, "sniff wait")

    for address in settings.dns:
        if not _is_ip(address):
            raise ProfileValidationError(f"DNS server '{address}' is not an IP address")

    # The proxy to dial through.
    if settings.upstream:
        upstream = parse_proxy_url(settings.upstream)
        if not upstream.is_socks and (mode in UDP_ONLY_MODES or settings.transport.lower() == "h3"):
            raise ProfileValidationError(
                "An HTTP proxy can't carry UDP, which "
                + (f"{mode.value} needs" if mode in UDP_ONLY_MODES else "HTTP/3 (QUIC) needs")
                + ". Use a socks5:// proxy, or the HTTP/2 carrier with the masque, gool or mim mode."
            )

    # Routing.
    for rule in (*settings.route_block, *settings.route_direct):
        parse_route_entry(rule)

    if settings.exit_loc:
        spec = settings.exit_loc.strip()
        if spec.lower() not in ("any", "off") and not _COUNTRIES.match(spec):
            raise ProfileValidationError(
                f"exit location '{settings.exit_loc}' must be country codes: '!IR,RU' to refuse those, "
                "'DE,SE' to allow only those"
            )

    if settings.mark and not _MARK.match(settings.mark):
        raise ProfileValidationError(f"mark '{settings.mark}' must be a number such as 255 or 0xff")
    if settings.api_address:
        _validate_api_address(settings.api_address)

    for key, value in settings.env.items():
        if not _ENV_NAME.match(key):
            raise ProfileValidationError(f"Extra setting '{key}' is not an AETHER_* variable name")
        if key in OWNED_ENV:
            raise ProfileValidationError(
                f"{key} is managed by v2rm (where Aether listens, keeps its state and dials out); "
                "use the profile's own options instead"
            )
        if "\x00" in value:
            raise ProfileValidationError(f"The value of {key} contains a NUL byte")


def _validate_api_address(value: str) -> None:
    text = value.strip()
    host, port = text, ""
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        port = rest.lstrip(":")
    elif text.count(":") == 1:
        host, _, port = text.partition(":")
    if port and (not port.isdigit() or not 1 <= int(port) <= 65535):
        raise ProfileValidationError(f"api address '{value}' has an invalid port")
    if not (_is_ip(host) or valid_domain(host)):
        raise ProfileValidationError(f"api address '{value}' is no IP address or domain name, with or without a port")


def validate_aether(profile: Profile) -> None:
    if profile.protocol != Protocol.AETHER or profile.aether is None:
        raise ProfileValidationError("Not an Aether profile")
    validate_settings(profile.aether)


def build_profile(settings: AetherSettings, name: str = "") -> Profile:
    """A validated Aether profile (`v2rm add aether`, the menu)."""
    validate_settings(settings)
    profile = Profile(
        name=name.strip() or settings.summary(),
        protocol=Protocol.AETHER,
        aether=settings,
    )
    return profile
