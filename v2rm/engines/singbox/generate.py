from __future__ import annotations

from typing import Any

from v2rm.constants import DEFAULT_LISTEN_ADDRESS, GEOIP_RULESET_BASE, GEOSITE_RULESET_BASE
from v2rm.errors import UnsupportedFeatureError, UnsupportedProtocolError
from v2rm.models.auth import ProxyAuth
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


# sing-box's uTLS fingerprint names. Xray also takes "unsafe" and a few more;
# anything else can't be expressed here and is reported, not dropped.
_UTLS_FINGERPRINTS = frozenset(
    {"chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android", "random", "randomized"}
)
_PACKET_ENCODINGS = {"xudp": "xudp", "packet": "packetaddr", "packetaddr": "packetaddr"}


def generate_config(
    profile: Profile,
    route_plan: RoutePlan,
    socks_port: int,
    http_port: int,
    listen_address: str = DEFAULT_LISTEN_ADDRESS,
    auth: ProxyAuth | None = None,
    notes: list[str] | None = None,
) -> dict[str, Any]:
    if profile.protocol not in SUPPORTED_PROTOCOLS:
        raise UnsupportedProtocolError(
            f"sing-box does not support '{profile.protocol.value}' profiles; "
            "use Xray-core for it (`v2rm core use xray`)."
        )
    _reject_xray_only_options(profile)

    rule_sets, rules = build_routing_rules(route_plan)

    return {
        "log": {"level": "warn"},
        "inbounds": _inbounds(socks_port, http_port, listen_address, auth),
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


def _inbounds(
    socks_port: int, http_port: int, listen_address: str, auth: ProxyAuth | None
) -> list[dict[str, Any]]:
    socks: dict[str, Any] = {"type": "socks", "tag": "socks-in", "listen": listen_address, "listen_port": socks_port}
    http: dict[str, Any] = {"type": "http", "tag": "http-in", "listen": listen_address, "listen_port": http_port}
    if auth is not None:
        socks["users"] = [{"username": auth.user, "password": auth.password}]
        http["users"] = [{"username": auth.user, "password": auth.password}]
    return [socks, http]


def _reject_xray_only_options(profile: Profile) -> None:
    """Profile options with no sing-box equivalent are reported as an error --
    quietly dropping them would connect the profile *without* e.g. its
    fragmentation or encryption and fail in confusing ways."""
    transport, tls = profile.transport, profile.tls
    unsupported: list[str] = []
    if transport.network in (TransportKind.XHTTP, TransportKind.KCP):
        unsupported.append(f"the '{transport.network.value}' transport")
    if transport.finalmask:
        unsupported.append("finalmask ('fm')")
    if tls.ech_config_list:
        unsupported.append("ECH ('ech'/'echConfigList')")
    if profile.encryption:
        unsupported.append("VLESS post-quantum encryption")
    if tls.fingerprint and tls.fingerprint.lower() not in _UTLS_FINGERPRINTS:
        unsupported.append(f"the '{tls.fingerprint}' TLS fingerprint")
    if unsupported:
        raise UnsupportedFeatureError(
            "sing-box doesn't support " + ", ".join(unsupported)
            + ", which this profile uses. Use Xray-core for it (`v2rm core use xray`)."
        )


def _outbound(profile: Profile) -> dict[str, Any]:
    base: dict[str, Any] = {"tag": "proxy", "server": profile.server, "server_port": profile.port}

    if profile.protocol == Protocol.VMESS:
        base["type"] = "vmess"
        base["uuid"] = profile.uuid
        base["alter_id"] = profile.alter_id
        base["security"] = profile.method or "auto"
        _apply_packet_encoding(base, profile)
    elif profile.protocol == Protocol.VLESS:
        base["type"] = "vless"
        base["uuid"] = profile.uuid
        if profile.flow:
            base["flow"] = profile.flow
        _apply_packet_encoding(base, profile)
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


def _apply_packet_encoding(base: dict[str, Any], profile: Profile) -> None:
    mapped = _PACKET_ENCODINGS.get((profile.packet_encoding or "").lower())
    if mapped:
        base["packet_encoding"] = mapped


def _host_and_headers(profile: Profile) -> tuple[str, dict[str, str]]:
    host = profile.transport.host
    headers: dict[str, str] = {}
    for key, value in profile.transport.headers.items():
        if key.lower() == "host":
            host = host or value
        else:
            headers[key] = value
    return host, headers


def _transport(profile: Profile) -> dict[str, Any] | None:
    network = profile.transport.network
    host, headers = _host_and_headers(profile)
    if network == TransportKind.TCP:
        return None
    if network == TransportKind.WS:
        d: dict[str, Any] = {"type": "ws", "path": profile.transport.path or "/"}
        ws_headers = dict(headers)
        if host:
            ws_headers["Host"] = host
        if ws_headers:
            d["headers"] = ws_headers
        return d
    if network == TransportKind.GRPC:
        return {"type": "grpc", "service_name": profile.transport.service_name}
    if network == TransportKind.HTTP:
        d = {"type": "http", "path": profile.transport.path or "/"}
        if host:
            d["host"] = [host]
        return d
    if network == TransportKind.HTTPUPGRADE:
        d = {"type": "httpupgrade", "path": profile.transport.path or "/", "host": host}
        if headers:
            d["headers"] = headers
        return d
    if network == TransportKind.QUIC:
        return {"type": "quic"}
    # xhttp/kcp are rejected up front by _reject_xray_only_options.
    raise UnsupportedFeatureError(f"sing-box doesn't support the '{network.value}' transport.")  # pragma: no cover


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
    if tls.cipher_suites:
        d["cipher_suites"] = [s for s in tls.cipher_suites.split(":") if s]
    if tls.fingerprint:
        d["utls"] = {"enabled": True, "fingerprint": tls.fingerprint.lower()}
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
