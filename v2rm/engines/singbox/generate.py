from __future__ import annotations

from typing import Any

from v2rm.constants import DEFAULT_LISTEN_ADDRESS, GEOIP_RULESET_BASE, GEOSITE_RULESET_BASE
from v2rm.errors import UnsupportedProtocolError
from v2rm.models.enums import Protocol, SecurityKind, TransportKind
from v2rm.models.profile import Profile
from v2rm.routing.model import RoutePlan

SUPPORTED_PROTOCOLS = frozenset(
    {
        Protocol.VMESS,
        Protocol.VLESS,
        Protocol.TROJAN,
        Protocol.SHADOWSOCKS,
        Protocol.HYSTERIA2,
        Protocol.TUIC,
    }
)


def generate_config(
    profile: Profile,
    route_plan: RoutePlan,
    socks_port: int,
    http_port: int,
    listen_address: str = DEFAULT_LISTEN_ADDRESS,
) -> dict[str, Any]:
    if profile.protocol not in SUPPORTED_PROTOCOLS:  # pragma: no cover - all Protocol values covered today
        raise UnsupportedProtocolError(f"sing-box does not support '{profile.protocol.value}' profiles.")

    rule_sets, rules = build_routing_rules(route_plan)

    return {
        "log": {"level": "warn"},
        "inbounds": [
            {"type": "socks", "tag": "socks-in", "listen": listen_address, "listen_port": socks_port},
            {"type": "http", "tag": "http-in", "listen": listen_address, "listen_port": http_port},
        ],
        "outbounds": [
            _outbound(profile),
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
        ],
        "route": {
            "rule_set": rule_sets,
            "rules": rules,
            "final": "proxy",
        },
    }


def _outbound(profile: Profile) -> dict[str, Any]:
    base: dict[str, Any] = {"tag": "proxy", "server": profile.server, "server_port": profile.port}

    if profile.protocol == Protocol.VMESS:
        base["type"] = "vmess"
        base["uuid"] = profile.uuid
        base["alter_id"] = profile.alter_id
        base["security"] = profile.method or "auto"
    elif profile.protocol == Protocol.VLESS:
        base["type"] = "vless"
        base["uuid"] = profile.uuid
        if profile.flow:
            base["flow"] = profile.flow
    elif profile.protocol == Protocol.TROJAN:
        base["type"] = "trojan"
        base["password"] = profile.password
    elif profile.protocol == Protocol.SHADOWSOCKS:
        base["type"] = "shadowsocks"
        base["method"] = profile.method
        base["password"] = profile.password
    elif profile.protocol == Protocol.HYSTERIA2:
        base["type"] = "hysteria2"
        base["password"] = profile.password
        if profile.extra.get("obfs"):
            base["obfs"] = {"type": profile.extra["obfs"], "password": profile.extra.get("obfs_password", "")}
    elif profile.protocol == Protocol.TUIC:
        base["type"] = "tuic"
        base["uuid"] = profile.uuid
        base["password"] = profile.password
        if profile.congestion_control:
            base["congestion_control"] = profile.congestion_control
    else:  # pragma: no cover - guarded by the SUPPORTED_PROTOCOLS check above
        raise UnsupportedProtocolError(f"sing-box does not support '{profile.protocol.value}'")

    transport = _transport(profile)
    if transport is not None:
        base["transport"] = transport

    tls = _tls(profile)
    if tls is not None:
        base["tls"] = tls
    elif profile.protocol in (Protocol.HYSTERIA2, Protocol.TUIC):
        # QUIC-based protocols are TLS-mandatory even if a profile somehow
        # carries an empty TlsSettings -- both parsers always set
        # security=TLS, but keep the generator defensive regardless.
        base["tls"] = {"enabled": True, "server_name": profile.server}

    return base


def _transport(profile: Profile) -> dict[str, Any] | None:
    network = profile.transport.network
    if network == TransportKind.TCP:
        return None
    if network == TransportKind.WS:
        d: dict[str, Any] = {"type": "ws", "path": profile.transport.path or "/"}
        if profile.transport.host:
            d["headers"] = {"Host": profile.transport.host}
        return d
    if network == TransportKind.GRPC:
        return {"type": "grpc", "service_name": profile.transport.service_name}
    if network == TransportKind.HTTP:
        d = {"type": "http", "path": profile.transport.path or "/"}
        if profile.transport.host:
            d["host"] = [profile.transport.host]
        return d
    if network == TransportKind.HTTPUPGRADE:
        return {"type": "httpupgrade", "path": profile.transport.path or "/", "host": profile.transport.host}
    if network == TransportKind.QUIC:
        return {"type": "quic"}
    # kcp has no sing-box equivalent, and xhttp support varies by version --
    # omit rather than emit a transport block that may not parse.
    return None


def _tls(profile: Profile) -> dict[str, Any] | None:
    tls = profile.tls
    if tls.security == SecurityKind.NONE:
        return None

    d: dict[str, Any] = {"enabled": True}
    if tls.sni:
        d["server_name"] = tls.sni
    if tls.alpn:
        d["alpn"] = list(tls.alpn)
    if tls.allow_insecure:
        d["insecure"] = True
    if tls.fingerprint:
        d["utls"] = {"enabled": True, "fingerprint": tls.fingerprint}
    if tls.security == SecurityKind.REALITY and tls.reality:
        d["reality"] = {
            "enabled": True,
            "public_key": tls.reality.public_key,
            "short_id": tls.reality.short_id,
        }
    return d


def build_routing_rules(route_plan: RoutePlan) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """sing-box ANDs distinct field *categories* within one rule object --
    `rule_set` in particular always ANDs against every other field on the
    same rule -- so each criteria list on a RouteRule becomes its own
    native rule here. Multiple tags *within* one list (e.g. two geoip tags)
    still share one `rule_set` array, which correctly ORs them."""
    rule_sets: dict[str, dict[str, Any]] = {}
    rules: list[dict[str, Any]] = []

    def ruleset_tag(prefix: str, name: str) -> str:
        tag = f"{prefix}-{name}"
        if tag not in rule_sets:
            base_url = GEOSITE_RULESET_BASE if prefix == "geosite" else GEOIP_RULESET_BASE
            rule_sets[tag] = {
                "type": "remote",
                "tag": tag,
                "format": "binary",
                "url": f"{base_url}/{tag}.srs",
                "download_detour": "direct",
            }
        return tag

    for rule in route_plan.rules:
        outbound = rule.kind
        if rule.domain_suffix:
            rules.append({"domain_suffix": list(rule.domain_suffix), "action": "route", "outbound": outbound})
        if rule.domain_keyword:
            rules.append({"domain_keyword": list(rule.domain_keyword), "action": "route", "outbound": outbound})
        if rule.geosite:
            tags = [ruleset_tag("geosite", tag) for tag in rule.geosite]
            rules.append({"rule_set": tags, "action": "route", "outbound": outbound})
        if rule.ip_cidr:
            rules.append({"ip_cidr": list(rule.ip_cidr), "action": "route", "outbound": outbound})
        if rule.geoip:
            tags = [ruleset_tag("geoip", tag) for tag in rule.geoip]
            rules.append({"rule_set": tags, "action": "route", "outbound": outbound})

    return list(rule_sets.values()), rules
