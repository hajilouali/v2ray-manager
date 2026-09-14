from __future__ import annotations

from typing import Any

import yaml

from v2rm.errors import ParseError
from v2rm.models.enums import Protocol, SecurityKind, TransportKind
from v2rm.models.profile import Profile, RealitySettings, TlsSettings, TransportSettings

_NETWORK_MAP = {
    "tcp": TransportKind.TCP,
    "ws": TransportKind.WS,
    "grpc": TransportKind.GRPC,
    "http": TransportKind.HTTP,
    "h2": TransportKind.HTTP,
    "httpupgrade": TransportKind.HTTPUPGRADE,
}

_TYPE_MAP = {
    "vmess": Protocol.VMESS,
    "vless": Protocol.VLESS,
    "trojan": Protocol.TROJAN,
    "ss": Protocol.SHADOWSOCKS,
    "shadowsocks": Protocol.SHADOWSOCKS,
    "hysteria2": Protocol.HYSTERIA2,
    "hy2": Protocol.HYSTERIA2,
    "tuic": Protocol.TUIC,
}


def parse_clash_yaml(text: str) -> tuple[list[Profile], list[tuple[str, str]]]:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ParseError(f"Invalid Clash YAML: {exc}") from exc

    if not isinstance(data, dict) or not isinstance(data.get("proxies"), list):
        raise ParseError("Clash YAML has no top-level 'proxies' list")

    profiles: list[Profile] = []
    errors: list[tuple[str, str]] = []
    for entry in data["proxies"]:
        label = str(entry.get("name", "?")) if isinstance(entry, dict) else "?"
        try:
            profiles.append(_parse_proxy(entry))
        except (ParseError, KeyError, TypeError, ValueError) as exc:
            errors.append((label, str(exc)))
    return profiles, errors


def _parse_proxy(entry: dict[str, Any]) -> Profile:
    raw_type = str(entry.get("type", "")).lower()
    protocol = _TYPE_MAP.get(raw_type)
    if protocol is None:
        raise ParseError(f"Unsupported Clash proxy type '{raw_type}'")

    server = str(entry.get("server", ""))
    port = int(entry.get("port", 0) or 0)
    if not server or not port:
        raise ParseError("Missing server/port")
    name = str(entry.get("name") or f"{server}:{port}")

    profile = Profile(
        name=name,
        protocol=protocol,
        server=server,
        port=port,
        transport=_transport(entry),
        tls=_tls(entry, protocol),
    )

    if protocol == Protocol.VMESS:
        profile.uuid = str(entry.get("uuid", ""))
        profile.alter_id = int(entry.get("alterId", 0) or 0)
        profile.method = str(entry.get("cipher", "auto") or "auto")
    elif protocol == Protocol.VLESS:
        profile.uuid = str(entry.get("uuid", ""))
        profile.flow = str(entry.get("flow", "") or "")
    elif protocol == Protocol.TROJAN:
        profile.password = str(entry.get("password", ""))
    elif protocol == Protocol.SHADOWSOCKS:
        profile.method = str(entry.get("cipher", ""))
        profile.password = str(entry.get("password", ""))
    elif protocol == Protocol.HYSTERIA2:
        profile.password = str(entry.get("password", "") or entry.get("auth", ""))
        if entry.get("obfs"):
            profile.extra["obfs"] = entry["obfs"]
        if entry.get("obfs-password"):
            profile.extra["obfs_password"] = entry["obfs-password"]
    elif protocol == Protocol.TUIC:
        profile.uuid = str(entry.get("uuid", ""))
        profile.password = str(entry.get("password", ""))
        profile.congestion_control = str(
            entry.get("congestion-controller", "") or entry.get("congestion_control", "")
        )

    return profile


def _transport(entry: dict[str, Any]) -> TransportSettings:
    network_raw = str(entry.get("network", "tcp") or "tcp").lower()
    network = _NETWORK_MAP.get(network_raw, TransportKind.TCP)

    path = ""
    host = ""
    service_name = ""

    if network == TransportKind.WS:
        opts = entry.get("ws-opts") or {}
        path = str(opts.get("path", "") or "")
        headers = opts.get("headers") or {}
        host = str(headers.get("Host", "") or headers.get("host", "") or "")
    elif network == TransportKind.GRPC:
        opts = entry.get("grpc-opts") or {}
        service_name = str(opts.get("grpc-service-name", "") or "")
    elif network == TransportKind.HTTP:
        opts = entry.get("http-opts") or {}
        raw_path = opts.get("path") or ""
        path = str(raw_path[0]) if isinstance(raw_path, list) and raw_path else str(raw_path)

    return TransportSettings(network=network, path=path, host=host, service_name=service_name)


def _tls(entry: dict[str, Any], protocol: Protocol) -> TlsSettings:
    reality_opts = entry.get("reality-opts")
    tls_enabled = bool(entry.get("tls", False))

    if reality_opts:
        security = SecurityKind.REALITY
    elif tls_enabled or protocol in (Protocol.HYSTERIA2, Protocol.TUIC, Protocol.TROJAN):
        security = SecurityKind.TLS
    else:
        security = SecurityKind.NONE

    reality = None
    if reality_opts:
        reality = RealitySettings(
            public_key=str(reality_opts.get("public-key", "") or ""),
            short_id=str(reality_opts.get("short-id", "") or ""),
        )

    sni = str(entry.get("sni", "") or entry.get("servername", "") or "")
    alpn = entry.get("alpn") or []
    if isinstance(alpn, str):
        alpn = [alpn]

    return TlsSettings(
        security=security,
        sni=sni,
        alpn=[str(a) for a in alpn],
        fingerprint=str(entry.get("client-fingerprint", "") or ""),
        allow_insecure=bool(entry.get("skip-cert-verify", False)),
        reality=reality,
    )
