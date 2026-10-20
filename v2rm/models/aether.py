"""The settings of an Aether profile.

Aether (CluvexStudio/Aether) opens a Cloudflare WARP tunnel -- over MASQUE (HTTP/3 or HTTP/2),
classic WireGuard, a WireGuard tunnel carried inside a MASQUE one ("gool"), WireGuard in
WireGuard ("gool-classic") or MASQUE in MASQUE -- finds a gateway that works by scanning, and
serves it as a local SOCKS5 proxy. There is no server to name: the "server" is Cloudflare's edge,
found at connect time. Everything here is what v2rm hands to the Aether process.

Empty strings and None mean "leave it to Aether's own default", so a stored profile stays
small and keeps following Aether's defaults as they change.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AetherMode(str, Enum):
    MASQUE = "masque"
    WG = "wg"
    GOOL = "gool"
    GOOL_CLASSIC = "gool-classic"
    MIM = "mim"


MODE_LABELS = {
    AetherMode.MASQUE: "WARP over MASQUE",
    AetherMode.WG: "WARP over WireGuard",
    AetherMode.GOOL: "gool (WireGuard inside MASQUE)",
    AetherMode.GOOL_CLASSIC: "gool-classic (WireGuard in WireGuard)",
    AetherMode.MIM: "MASQUE in MASQUE",
}

# Modes that ride on a MASQUE tunnel and so can use HTTP/3 (QUIC, UDP) or HTTP/2 (TCP).
MASQUE_MODES = frozenset({AetherMode.MASQUE, AetherMode.GOOL, AetherMode.MIM})
# Modes that are UDP all the way to Cloudflare.
UDP_ONLY_MODES = frozenset({AetherMode.WG, AetherMode.GOOL_CLASSIC})
# Modes with two hops (an outer one your network sees, an inner one it does not).
TWO_HOP_MODES = frozenset({AetherMode.GOOL, AetherMode.GOOL_CLASSIC, AetherMode.MIM})

TRANSPORTS = ("h3", "h2")
SCAN_MODES = ("turbo", "balanced", "thorough", "verified", "ironclad")
IP_VERSIONS = ("v4", "v6", "both")
NOIZE_PROFILES = ("off", "light", "firewall", "balanced", "gfw", "aggressive")
PERF_PROFILES = ("low", "medium", "high")
LOG_LEVELS = ("error", "warn", "info", "debug", "trace")


def _str(data: dict[str, Any], key: str, default: str = "") -> str:
    value = data.get(key, default)
    return "" if value is None else str(value)


def _opt_int(data: dict[str, Any], key: str) -> int | None:
    value = data.get(key)
    if value in (None, "", 0):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _str_list(data: dict[str, Any], key: str) -> list[str]:
    value = data.get(key) or []
    if isinstance(value, str):
        value = [value]
    return [str(v) for v in value if str(v).strip()]


@dataclass
class AetherSettings:
    mode: AetherMode = AetherMode.MASQUE

    # MASQUE carrier: "" = Aether's default (HTTP/3), "h3", "h2".
    transport: str = ""
    # Gateways by hand, each "ip:port" (the port is required: which one gets through differs
    # between networks). Empty = find them by scanning. What they mean depends on the mode, see
    # v2rm.engines.aether.env: masque/wg -> the gateway; gool -> the MASQUE gateway (outer) and
    # the WireGuard endpoint dialled inside it (inner); gool-classic/mim -> outer and inner hop.
    outer: str = ""
    inner: str = ""
    # Gateway of the HTTP/2 carrier, when it differs from the HTTP/3 one.
    h2_peer: str = ""

    # Scanning: how hard to look for a working gateway, and over which IP version.
    scan: str = ""
    ip: str = ""

    # Traffic obfuscation profile (Aether's "noize").
    noize: str = ""

    # TLS ClientHello fragmentation, for the HTTP/2 carrier and the registration calls.
    fragment: bool = False
    fragment_size: str = ""  # bytes: "8-16" or "10"
    fragment_delay: str = ""  # ms: "2-10" or "5"

    # TLS knobs of the tunnel handshakes.
    sni: str = ""
    ech: str = ""  # "auto" or a base64 config
    ech_dns: str = ""
    ech_domain: str = ""
    tls_ciphers: str = ""
    tls_groups: str = ""
    disable_grease: bool = False
    quic_v2: bool = True

    # Reconnecting: Aether re-establishes a dropped tunnel by itself; "quick" reconnect tries the
    # gateways that worked last time before it scans again.
    quick_reconnect: bool = True
    reconnect_secs: int | None = None
    startup_secs: int | None = None
    validate_secs: int | None = None
    no_data_check: bool = False
    keepalive: int | None = None
    dns: list[str] = field(default_factory=list)

    # A proxy already running on this machine (another VPN, a Tor client, ...) to dial out
    # through: "socks5://127.0.0.1:1080" or "http://user:pass@host:8080".
    upstream: str = ""

    # Routing rules, matched on the destination name (read from the TLS ServerName / HTTP Host
    # when the client only gave an address, so they work behind a tun front end), address or port.
    route_block: list[str] = field(default_factory=list)
    route_direct: list[str] = field(default_factory=list)
    route_sniff: bool = True
    route_sniff_ms: int | None = None

    # Refuse a tunnel whose exit is in the wrong country: "!IR,RU" blocks, "DE,SE" allows only.
    exit_loc: str = ""
    exit_loc_secs: int | None = None

    # Linux fwmark on Aether's own sockets, and where the WARP API calls go.
    mark: str = ""
    api_address: str = ""
    perf: str = ""
    stats: bool = False
    log_level: str = ""

    # Any other AETHER_* environment variable (Zero Trust, Tor, Psiphon, ...), passed as is.
    env: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode.value,
            "transport": self.transport,
            "outer": self.outer,
            "inner": self.inner,
            "h2_peer": self.h2_peer,
            "scan": self.scan,
            "ip": self.ip,
            "noize": self.noize,
            "fragment": self.fragment,
            "fragment_size": self.fragment_size,
            "fragment_delay": self.fragment_delay,
            "sni": self.sni,
            "ech": self.ech,
            "ech_dns": self.ech_dns,
            "ech_domain": self.ech_domain,
            "tls_ciphers": self.tls_ciphers,
            "tls_groups": self.tls_groups,
            "disable_grease": self.disable_grease,
            "quic_v2": self.quic_v2,
            "quick_reconnect": self.quick_reconnect,
            "reconnect_secs": self.reconnect_secs,
            "startup_secs": self.startup_secs,
            "validate_secs": self.validate_secs,
            "no_data_check": self.no_data_check,
            "keepalive": self.keepalive,
            "dns": list(self.dns),
            "upstream": self.upstream,
            "route_block": list(self.route_block),
            "route_direct": list(self.route_direct),
            "route_sniff": self.route_sniff,
            "route_sniff_ms": self.route_sniff_ms,
            "exit_loc": self.exit_loc,
            "exit_loc_secs": self.exit_loc_secs,
            "mark": self.mark,
            "api_address": self.api_address,
            "perf": self.perf,
            "stats": self.stats,
            "log_level": self.log_level,
            "env": copy.deepcopy(self.env),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> AetherSettings:
        """Tolerant on purpose: a stored profile may come from an older or newer v2rm, or from
        a hand edit, so unknown keys are ignored and missing ones take their defaults."""
        data = data or {}
        try:
            mode = AetherMode(str(data.get("mode") or AetherMode.MASQUE.value))
        except ValueError:
            mode = AetherMode.MASQUE
        env = data.get("env") or {}
        return cls(
            mode=mode,
            transport=_str(data, "transport"),
            outer=_str(data, "outer"),
            inner=_str(data, "inner"),
            h2_peer=_str(data, "h2_peer"),
            scan=_str(data, "scan"),
            ip=_str(data, "ip"),
            noize=_str(data, "noize"),
            fragment=bool(data.get("fragment", False)),
            fragment_size=_str(data, "fragment_size"),
            fragment_delay=_str(data, "fragment_delay"),
            sni=_str(data, "sni"),
            ech=_str(data, "ech"),
            ech_dns=_str(data, "ech_dns"),
            ech_domain=_str(data, "ech_domain"),
            tls_ciphers=_str(data, "tls_ciphers"),
            tls_groups=_str(data, "tls_groups"),
            disable_grease=bool(data.get("disable_grease", False)),
            quic_v2=bool(data.get("quic_v2", True)),
            quick_reconnect=bool(data.get("quick_reconnect", True)),
            reconnect_secs=_opt_int(data, "reconnect_secs"),
            startup_secs=_opt_int(data, "startup_secs"),
            validate_secs=_opt_int(data, "validate_secs"),
            no_data_check=bool(data.get("no_data_check", False)),
            keepalive=_opt_int(data, "keepalive"),
            dns=_str_list(data, "dns"),
            upstream=_str(data, "upstream"),
            route_block=_str_list(data, "route_block"),
            route_direct=_str_list(data, "route_direct"),
            route_sniff=bool(data.get("route_sniff", True)),
            route_sniff_ms=_opt_int(data, "route_sniff_ms"),
            exit_loc=_str(data, "exit_loc"),
            exit_loc_secs=_opt_int(data, "exit_loc_secs"),
            mark=_str(data, "mark"),
            api_address=_str(data, "api_address"),
            perf=_str(data, "perf"),
            stats=bool(data.get("stats", False)),
            log_level=_str(data, "log_level"),
            env={str(k): str(v) for k, v in env.items()} if isinstance(env, dict) else {},
        )

    @property
    def label(self) -> str:
        return MODE_LABELS[self.mode]

    def summary(self) -> str:
        """A short description for the profile list's Server column: what it is and how."""
        parts = [self.mode.value]
        if self.mode in MASQUE_MODES and self.transport:
            parts.append(self.transport)
        if self.fragment:
            parts.append("fragment")
        if self.noize:
            parts.append(f"noize:{self.noize}")
        return "WARP " + "/".join(parts[:2]) + ("".join(f" +{p}" for p in parts[2:]))
