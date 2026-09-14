from __future__ import annotations

import json

from v2rm.errors import ParseError
from v2rm.models.enums import Protocol, SecurityKind, TransportKind
from v2rm.models.profile import Profile, TlsSettings, TransportSettings
from v2rm.parsers import links

SCHEME = "vmess"


def parse(link: str) -> Profile:
    if not link.startswith("vmess://"):
        raise ParseError("Not a vmess:// link")
    payload = link[len("vmess://") :].strip()
    text = links.b64_decode_text(payload)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ParseError(f"vmess payload is not valid JSON: {exc}") from exc

    server = str(data.get("add", "") or "").strip()
    if not server:
        raise ParseError("vmess link is missing 'add' (server host)")
    try:
        port = int(data.get("port", 0))
    except (TypeError, ValueError) as exc:
        raise ParseError(f"vmess link has an invalid port: {data.get('port')!r}") from exc
    if not port:
        raise ParseError("vmess link is missing a port")

    net_raw = str(data.get("net", "tcp") or "tcp").lower()
    network = links.NETWORK_MAP.get(net_raw, TransportKind.TCP)

    path = str(data.get("path", "") or "")
    host = str(data.get("host", "") or "")
    service_name = ""
    if network == TransportKind.GRPC:
        service_name, path = path, ""

    tls_raw = str(data.get("tls", "") or "").lower()
    security = SecurityKind.TLS if tls_raw in ("tls", "reality") else SecurityKind.NONE
    sni = str(data.get("sni", "") or "") or host

    alpn_raw = str(data.get("alpn", "") or "")
    alpn = [v.strip() for v in alpn_raw.split(",") if v.strip()]

    extra: dict = {}
    header_type = str(data.get("type", "") or "")
    if header_type and header_type != "none":
        extra["header_type"] = header_type

    name = str(data.get("ps", "") or "").strip() or f"{server}:{port}"

    return Profile(
        name=name,
        protocol=Protocol.VMESS,
        server=server,
        port=port,
        raw_link=link,
        uuid=str(data.get("id", "") or ""),
        alter_id=int(data.get("aid", 0) or 0),
        method=str(data.get("scy", "") or "auto"),
        transport=TransportSettings(network=network, path=path, host=host, service_name=service_name),
        tls=TlsSettings(
            security=security,
            sni=sni,
            alpn=alpn,
            fingerprint=str(data.get("fp", "") or ""),
        ),
        extra=extra,
    )


def to_link(profile: Profile) -> str:
    is_grpc = profile.transport.network == TransportKind.GRPC
    data = {
        "v": "2",
        "ps": profile.name,
        "add": profile.server,
        "port": str(profile.port),
        "id": profile.uuid,
        "aid": str(profile.alter_id),
        "scy": profile.method or "auto",
        "net": profile.transport.network.value,
        "type": profile.extra.get("header_type", "none"),
        "host": profile.transport.host,
        "path": profile.transport.service_name if is_grpc else profile.transport.path,
        "tls": "tls" if profile.tls.security != SecurityKind.NONE else "",
        "sni": profile.tls.sni,
        "alpn": ",".join(profile.tls.alpn),
        "fp": profile.tls.fingerprint,
    }
    encoded = links.b64_encode_std(json.dumps(data, ensure_ascii=False))
    return f"vmess://{encoded}"
