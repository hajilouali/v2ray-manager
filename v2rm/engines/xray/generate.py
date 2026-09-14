from __future__ import annotations

from typing import Any

from v2rm.errors import UnsupportedProtocolError
from v2rm.models.enums import Protocol, SecurityKind, TransportKind
from v2rm.models.profile import Profile, TlsSettings
from v2rm.routing.model import RoutePlan

SUPPORTED_PROTOCOLS = frozenset(
    {Protocol.VMESS, Protocol.VLESS, Protocol.TROJAN, Protocol.SHADOWSOCKS}
)


def generate_config(
    profile: Profile, route_plan: RoutePlan, socks_port: int, http_port: int
) -> dict[str, Any]:
    if profile.protocol not in SUPPORTED_PROTOCOLS:
        raise UnsupportedProtocolError(
            f"Xray-core does not support '{profile.protocol.value}' profiles; use sing-box instead."
        )

    return {
        "log": {"loglevel": "warning"},
        "inbounds": _inbounds(socks_port, http_port),
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


def _inbounds(socks_port: int, http_port: int) -> list[dict[str, Any]]:
    sniffing = {"enabled": True, "destOverride": ["http", "tls"]}
    return [
        {
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True},
            "sniffing": sniffing,
        },
        {
            "tag": "http-in",
            "listen": "127.0.0.1",
            "port": http_port,
            "protocol": "http",
            "settings": {},
            "sniffing": sniffing,
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
        user: dict[str, Any] = {"id": profile.uuid, "encryption": "none"}
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
    else:  # pragma: no cover - guarded by the SUPPORTED_PROTOCOLS check above
        raise UnsupportedProtocolError(f"Xray-core does not support '{profile.protocol.value}'")

    stream = _stream_settings(profile)
    if stream is not None:
        base["streamSettings"] = stream
    return base


def _stream_settings(profile: Profile) -> dict[str, Any] | None:
    transport = profile.transport
    tls = profile.tls

    if transport.network == TransportKind.TCP and tls.security == SecurityKind.NONE:
        return None

    settings: dict[str, Any] = {"network": transport.network.value}

    if transport.network == TransportKind.WS:
        headers = {"Host": transport.host} if transport.host else {}
        settings["wsSettings"] = {"path": transport.path or "/", "headers": headers}
    elif transport.network == TransportKind.GRPC:
        settings["grpcSettings"] = {"serviceName": transport.service_name}
    elif transport.network == TransportKind.HTTP:
        settings["httpSettings"] = {
            "path": transport.path or "/",
            "host": [transport.host] if transport.host else [],
        }
    elif transport.network == TransportKind.HTTPUPGRADE:
        settings["httpupgradeSettings"] = {"path": transport.path or "/", "host": transport.host}
    elif transport.network == TransportKind.XHTTP:
        settings["xhttpSettings"] = {"path": transport.path or "/", "host": transport.host}
    elif transport.network == TransportKind.KCP:
        settings["kcpSettings"] = {}
    elif transport.network == TransportKind.QUIC:
        settings["quicSettings"] = {}

    if tls.security == SecurityKind.TLS:
        settings["security"] = "tls"
        settings["tlsSettings"] = _tls_settings(tls)
    elif tls.security == SecurityKind.REALITY:
        settings["security"] = "reality"
        settings["realitySettings"] = _reality_settings(tls)

    return settings


def _tls_settings(tls: TlsSettings) -> dict[str, Any]:
    d: dict[str, Any] = {}
    if tls.sni:
        d["serverName"] = tls.sni
    if tls.alpn:
        d["alpn"] = list(tls.alpn)
    if tls.fingerprint:
        d["fingerprint"] = tls.fingerprint
    if tls.allow_insecure:
        d["allowInsecure"] = True
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
