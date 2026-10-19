from __future__ import annotations

import copy
from typing import Any

from v2rm.constants import DEFAULT_LISTEN_ADDRESS
from v2rm.engines.xray.raw import account_settings, build_raw_runtime_config, udp_associate_address
from v2rm.errors import UnsupportedFeatureError, UnsupportedProtocolError
from v2rm.models.auth import ProxyAuth
from v2rm.models.enums import Protocol, SecurityKind, TransportKind
from v2rm.models.profile import Profile, TlsSettings
from v2rm.parsers.masque import DEFAULT_ALPN as MASQUE_DEFAULT_ALPN
from v2rm.parsers.masque import validate_masque
from v2rm.routing.model import RoutePlan

SUPPORTED_PROTOCOLS = frozenset(
    {
        Protocol.VMESS,
        Protocol.VLESS,
        Protocol.TROJAN,
        Protocol.SHADOWSOCKS,
        Protocol.MASQUE,
        Protocol.RAW_XRAY,
    }
)

# Xray `network` names for the transports it still has. TransportKind.HTTP
# (h2) and QUIC were removed upstream (the config loader refuses them).
_NETWORKS = {
    TransportKind.TCP: "tcp",
    TransportKind.WS: "ws",
    TransportKind.GRPC: "grpc",
    TransportKind.KCP: "kcp",
    TransportKind.HTTPUPGRADE: "httpupgrade",
    TransportKind.XHTTP: "xhttp",
}

_XHTTP_MODES = {"auto", "packet-up", "stream-up", "stream-one"}


def generate_config(
    profile: Profile,
    route_plan: RoutePlan,
    socks_port: int,
    http_port: int,
    listen_address: str = DEFAULT_LISTEN_ADDRESS,
    auth: ProxyAuth | None = None,
    notes: list[str] | None = None,
) -> dict[str, Any]:
    """Build the whole runtime config. `notes`, if given, collects one-line
    messages about things that were ignored/rewritten, for the caller to show."""
    if profile.protocol not in SUPPORTED_PROTOCOLS:
        raise UnsupportedProtocolError(
            f"Xray-core does not support '{profile.protocol.value}' profiles; use sing-box instead."
        )
    if notes is None:
        notes = []

    if profile.protocol == Protocol.RAW_XRAY:
        # Raw profiles carry their own routing/dns/outbounds; presets don't apply.
        return build_raw_runtime_config(profile, socks_port, http_port, listen_address, auth, notes)

    _collect_notes(profile, notes)
    return {
        "log": {"loglevel": "warning"},
        "inbounds": _inbounds(socks_port, http_port, listen_address, auth),
        "outbounds": [
            _outbound(profile),
            {"tag": "direct", "protocol": "freedom", "settings": {}},
            {"tag": "block", "protocol": "blackhole", "settings": {"response": {"type": "http"}}},
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": build_routing_rules(route_plan),
        },
    }


def needs_preflight(profile: Profile) -> bool:
    """Profiles whose config leans on newer-core-only or unusual features are
    validated with `xray run -test` before the engine is started."""
    return (
        profile.protocol in (Protocol.RAW_XRAY, Protocol.MASQUE)
        or bool(profile.transport.finalmask)
        or bool(profile.tls.ech_config_list)
        or bool(profile.encryption)
        or profile.transport.network == TransportKind.XHTTP
    )


def _collect_notes(profile: Profile, notes: list[str]) -> None:
    if profile.extra.get("fragment"):
        notes.append(
            f"Ignored the legacy 'fragment={profile.extra['fragment']}' parameter (no faithful "
            "finalmask equivalent); only 'fm' (finalmask) fragmentation is applied."
        )
    encoding = (profile.packet_encoding or "").lower()
    if encoding and encoding != "xudp":
        notes.append(f"packetEncoding={profile.packet_encoding} isn't configurable on Xray-core (UDP uses XUDP); ignored.")
    if profile.extra.get("header_type"):
        notes.append(f"Ignored headerType={profile.extra['header_type']} (TCP header obfuscation isn't generated).")


def _inbounds(
    socks_port: int, http_port: int, listen_address: str, auth: ProxyAuth | None
) -> list[dict[str, Any]]:
    sniffing = {"enabled": True, "destOverride": ["http", "tls"]}
    socks_settings: dict[str, Any] = {"auth": "noauth", "udp": True}
    http_settings: dict[str, Any] = {}
    ip = udp_associate_address(listen_address)
    if ip:
        socks_settings["ip"] = ip
    if auth is not None:
        socks_settings.update(account_settings("socks", auth))
        http_settings.update(account_settings("http", auth))
    return [
        {
            "tag": "socks-in",
            "listen": listen_address,
            "port": socks_port,
            "protocol": "socks",
            "settings": socks_settings,
            "sniffing": sniffing,
        },
        {
            "tag": "http-in",
            "listen": listen_address,
            "port": http_port,
            "protocol": "http",
            "settings": http_settings,
            "sniffing": copy.deepcopy(sniffing),
        },
    ]


def _outbound(profile: Profile) -> dict[str, Any]:
    base: dict[str, Any] = {"tag": "proxy"}

    if profile.protocol == Protocol.VMESS:
        base["protocol"] = "vmess"
        base["settings"] = {
            "vnext": [
                {
                    "address": profile.server,
                    "port": profile.port,
                    "users": [
                        {
                            "id": profile.uuid,
                            "alterId": profile.alter_id,
                            "security": profile.method or "auto",
                        }
                    ],
                }
            ]
        }
    elif profile.protocol == Protocol.VLESS:
        # "none", or a post-quantum string (mlkem768x25519plus...) verbatim.
        user: dict[str, Any] = {"id": profile.uuid, "encryption": profile.encryption or "none"}
        if profile.flow:
            user["flow"] = profile.flow
        base["protocol"] = "vless"
        base["settings"] = {"vnext": [{"address": profile.server, "port": profile.port, "users": [user]}]}
    elif profile.protocol == Protocol.TROJAN:
        base["protocol"] = "trojan"
        base["settings"] = {
            "servers": [{"address": profile.server, "port": profile.port, "password": profile.password}]
        }
    elif profile.protocol == Protocol.SHADOWSOCKS:
        base["protocol"] = "shadowsocks"
        base["settings"] = {
            "servers": [
                {
                    "address": profile.server,
                    "port": profile.port,
                    "method": profile.method,
                    "password": profile.password,
                }
            ]
        }
    elif profile.protocol == Protocol.MASQUE:
        validate_masque(profile)
        base["protocol"] = "masque"
        settings: dict[str, Any] = {"address": profile.server, "port": profile.port}
        if profile.extra.get("remote_dns"):
            settings["remoteDNS"] = list(profile.extra["remote_dns"])
        base["settings"] = settings
        base["streamSettings"] = _masque_stream_settings(profile)
        return base
    else:  # pragma: no cover - guarded by the SUPPORTED_PROTOCOLS check above
        raise UnsupportedProtocolError(f"Xray-core does not support '{profile.protocol.value}'")

    stream = _stream_settings(profile)
    if stream is not None:
        base["streamSettings"] = stream
    return base


def _split_host_header(profile: Profile) -> tuple[str, dict[str, str]]:
    """Xray wants the Host as the transport's independent `host` field: a
    `Host` entry in `headers` is deprecated for ws and an outright error for
    xhttp/httpupgrade. Fold it into `host` (an explicit host wins) and return
    the remaining headers."""
    host = profile.transport.host
    headers: dict[str, str] = {}
    for key, value in profile.transport.headers.items():
        if key.lower() == "host":
            host = host or value
        else:
            headers[key] = value
    return host, headers


def _stream_settings(profile: Profile) -> dict[str, Any] | None:
    transport = profile.transport
    tls = profile.tls

    network = _NETWORKS.get(transport.network)
    if network is None:
        raise UnsupportedFeatureError(
            f"Xray-core has removed the '{transport.network.value}' transport. Use sing-box for this "
            "profile (`v2rm core use singbox`), or ask the provider for an xhttp/ws endpoint."
        )

    has_mask = bool(transport.finalmask)
    if network == "tcp" and tls.security == SecurityKind.NONE and not has_mask:
        return None

    settings: dict[str, Any] = {"network": network}
    host, headers = _split_host_header(profile)

    if transport.network == TransportKind.WS:
        ws: dict[str, Any] = {"path": transport.path or "/"}
        if host:
            ws["host"] = host
        if headers:
            ws["headers"] = headers
        settings["wsSettings"] = ws
    elif transport.network == TransportKind.GRPC:
        settings["grpcSettings"] = {"serviceName": transport.service_name}
    elif transport.network == TransportKind.HTTPUPGRADE:
        hu: dict[str, Any] = {"path": transport.path or "/"}
        if host:
            hu["host"] = host
        if headers:
            hu["headers"] = headers
        settings["httpupgradeSettings"] = hu
    elif transport.network == TransportKind.XHTTP:
        settings["xhttpSettings"] = _xhttp_settings(profile, host, headers)
    elif transport.network == TransportKind.KCP:
        settings["kcpSettings"] = {}

    if tls.security == SecurityKind.TLS:
        settings["security"] = "tls"
        settings["tlsSettings"] = _tls_settings(tls)
    elif tls.security == SecurityKind.REALITY:
        settings["security"] = "reality"
        settings["realitySettings"] = _reality_settings(tls)

    if has_mask:
        settings["finalmask"] = copy.deepcopy(transport.finalmask)
    return settings


def _xhttp_settings(profile: Profile, host: str, headers: dict[str, str]) -> dict[str, Any]:
    transport = profile.transport
    xhttp: dict[str, Any] = {"path": transport.path or "/"}
    if host:
        xhttp["host"] = host
    if transport.mode in _XHTTP_MODES:
        xhttp["mode"] = transport.mode
    extra = copy.deepcopy(transport.xhttp_extra)
    if extra:
        # In Xray an `extra` object *replaces* the whole outer xhttp config
        # except host/path/mode, so custom headers must live inside it.
        if headers:
            extra["headers"] = {**extra.get("headers", {}), **headers}
        xhttp["extra"] = extra
    elif headers:
        xhttp["headers"] = headers
    return xhttp


def _tls_settings(tls: TlsSettings, default_alpn: list[str] | None = None) -> dict[str, Any]:
    if tls.allow_insecure:
        # Removed upstream: Xray-core refuses to start with allowInsecure set.
        raise UnsupportedFeatureError(
            "This profile needs 'allowInsecure' (skip certificate verification), which Xray-core "
            "has removed. Use sing-box for it (`v2rm core use singbox`), or ask the provider for a "
            "valid certificate."
        )
    d: dict[str, Any] = {}
    if tls.sni:
        d["serverName"] = tls.sni
    alpn = tls.alpn or default_alpn
    if alpn:
        d["alpn"] = list(alpn)
    if tls.fingerprint:
        d["fingerprint"] = tls.fingerprint
    if tls.cipher_suites:
        d["cipherSuites"] = tls.cipher_suites
    if tls.ech_config_list:
        d["echConfigList"] = tls.ech_config_list
    return d


def _reality_settings(tls: TlsSettings) -> dict[str, Any]:
    d: dict[str, Any] = {"serverName": tls.sni}
    if tls.fingerprint:
        d["fingerprint"] = tls.fingerprint
    if tls.reality:
        d["publicKey"] = tls.reality.public_key
        if tls.reality.short_id:
            d["shortId"] = tls.reality.short_id
        if tls.reality.spider_x:
            d["spiderX"] = tls.reality.spider_x
    return d


def _masque_stream_settings(profile: Profile) -> dict[str, Any]:
    """MASQUE is its own transport and TLS-only. alpn defaults to ["h2"]:
    h2 *without* h3 selects HTTP/2 Extended CONNECT, anything else HTTP/3."""
    transport = profile.transport
    masque: dict[str, Any] = {}
    if transport.host:
        masque["host"] = transport.host
    if transport.path:
        masque["path"] = transport.path
    user = str(profile.extra.get("user", ""))
    if user:
        masque["user"] = user
    if profile.password:
        masque["pass"] = profile.password
    if transport.headers:
        masque["headers"] = dict(transport.headers)
    if profile.extra.get("warp"):
        masque["warp"] = copy.deepcopy(profile.extra["warp"])

    settings: dict[str, Any] = {
        "network": "masque",
        "security": "tls",
        "tlsSettings": _tls_settings(profile.tls, default_alpn=list(MASQUE_DEFAULT_ALPN)),
        "masqueSettings": masque,
    }
    if transport.finalmask:
        settings["finalmask"] = copy.deepcopy(transport.finalmask)
    return settings


def build_routing_rules(route_plan: RoutePlan) -> list[dict[str, Any]]:
    """Xray ORs every entry within its `domain` array (and within `ip`), but
    ANDs a rule's `domain` against its `ip` -- so domain-type and ip-type
    criteria from one RouteRule become two separate rule objects here."""
    rules: list[dict[str, Any]] = []

    for rule in route_plan.rules:
        if rule.has_domain_criteria():
            domain_values: list[str] = []
            domain_values.extend(f"domain:{d}" for d in rule.domain_suffix)
            domain_values.extend(f"keyword:{k}" for k in rule.domain_keyword)
            domain_values.extend(f"geosite:{g}" for g in rule.geosite)
            rules.append({"type": "field", "domain": domain_values, "outboundTag": rule.kind})

        if rule.has_ip_criteria():
            ip_values: list[str] = []
            ip_values.extend(rule.ip_cidr)
            ip_values.extend(f"geoip:{g}" for g in rule.geoip)
            rules.append({"type": "field", "ip": ip_values, "outboundTag": rule.kind})

    # Xray-core (confirmed on 26.3.27) refuses to start a rule with no
    # "effective fields" at all -- a bare outboundTag doesn't count, even
    # as an intentional catch-all -- so the fallback rule needs a real
    # matching field. port: 0-65535 matches literally every connection.
    rules.append({"type": "field", "outboundTag": "proxy", "port": "0-65535"})
    return rules
