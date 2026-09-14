from __future__ import annotations

import base64
import binascii
from urllib.parse import SplitResult, parse_qs, quote, unquote, urlencode, urlsplit

from v2rm.errors import ParseError
from v2rm.models.enums import SecurityKind, TransportKind
from v2rm.models.profile import RealitySettings, TlsSettings, TransportSettings

# -- base64 -----------------------------------------------------------------
# urlsafe_b64decode transparently handles both the standard (+/) and
# URL-safe (-_) alphabets: it only translates -_ to +/ before delegating to
# the standard decoder, so a standard-alphabet input passes through
# unchanged. One decoder, no guessing which variant a client used.


def b64_decode_text(s: str) -> str:
    cleaned = s.strip().replace("\n", "").replace("\r", "").replace(" ", "")
    padded = cleaned + "=" * (-len(cleaned) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError) as exc:
        raise ParseError(f"Invalid base64 payload: {exc}") from exc
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ParseError(f"Base64 payload is not valid UTF-8: {exc}") from exc


def b64_encode_urlsafe(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode("utf-8")).decode("ascii").rstrip("=")


def b64_encode_std(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


# -- URI parsing --------------------------------------------------------------


def split_uri(link: str) -> SplitResult:
    try:
        return urlsplit(link.strip())
    except ValueError as exc:
        raise ParseError(f"Malformed link: {exc}") from exc


def userinfo(parsed: SplitResult) -> str:
    return unquote(parsed.username) if parsed.username else ""


def userinfo_password(parsed: SplitResult) -> str:
    return unquote(parsed.password) if parsed.password else ""


def host_and_port(parsed: SplitResult, link: str) -> tuple[str, int]:
    if not parsed.hostname:
        raise ParseError(f"Link is missing a host: {link}")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ParseError(f"Link has an invalid port: {exc}") from exc
    if not port:
        raise ParseError(f"Link is missing a port: {link}")
    return parsed.hostname, port


def split_host_port(hostport: str) -> tuple[str, int]:
    hostport = hostport.strip()
    if hostport.startswith("["):
        host, _, rest = hostport[1:].partition("]")
        port_str = rest.lstrip(":")
    else:
        host, _, port_str = hostport.rpartition(":")
    if not host or not port_str:
        raise ParseError(f"Could not split host/port from '{hostport}'")
    try:
        return host, int(port_str)
    except ValueError as exc:
        raise ParseError(f"Invalid port in '{hostport}'") from exc


def query_dict(parsed: SplitResult) -> dict[str, str]:
    raw = parse_qs(parsed.query, keep_blank_values=True)
    return {k: v[0] for k, v in raw.items() if v}


def remark(parsed: SplitResult, default: str) -> str:
    if parsed.fragment:
        decoded = unquote(parsed.fragment).strip()
        if decoded:
            return decoded
    return default


def split_alpn(value: str | None) -> list[str]:
    # `value` comes from query_dict(), which already ran it through parse_qs's
    # own percent-decoding -- no second unquote() needed here.
    if not value:
        return []
    return [v.strip() for v in value.split(",") if v.strip()]


def truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def build_link(scheme: str, userinfo_part: str, host: str, port: int, params: dict[str, str], name: str) -> str:
    query = urlencode(params)
    frag = quote(name)
    host_part = f"[{host}]" if ":" in host else host
    suffix = f"?{query}" if query else ""
    return f"{scheme}://{userinfo_part}@{host_part}:{port}{suffix}#{frag}"


# -- shared transport/TLS query-param mapping --------------------------------
# vless, trojan, hysteria2 and tuic all describe transport (type/path/host/
# serviceName) and TLS (security/sni/fp/alpn/reality) the same way; parsed
# once here instead of four times.

NETWORK_MAP: dict[str, TransportKind] = {
    "tcp": TransportKind.TCP,
    "ws": TransportKind.WS,
    "grpc": TransportKind.GRPC,
    "h2": TransportKind.HTTP,
    "http": TransportKind.HTTP,
    "kcp": TransportKind.KCP,
    "quic": TransportKind.QUIC,
    "httpupgrade": TransportKind.HTTPUPGRADE,
    "xhttp": TransportKind.XHTTP,
    "splithttp": TransportKind.XHTTP,
}


def parse_transport(q: dict[str, str]) -> TransportSettings:
    network = NETWORK_MAP.get((q.get("type") or "tcp").lower(), TransportKind.TCP)
    return TransportSettings(
        network=network,
        path=q.get("path", ""),
        host=q.get("host", ""),
        service_name=q.get("serviceName", ""),
    )


def transport_query_params(transport: TransportSettings) -> dict[str, str]:
    params: dict[str, str] = {}
    if transport.network != TransportKind.TCP:
        params["type"] = transport.network.value
    if transport.path:
        params["path"] = transport.path
    if transport.host:
        params["host"] = transport.host
    if transport.service_name:
        params["serviceName"] = transport.service_name
    return params


def parse_tls(q: dict[str, str], *, default_security: SecurityKind = SecurityKind.NONE) -> TlsSettings:
    security_raw = (q.get("security") or "").lower()
    if security_raw == "tls":
        security = SecurityKind.TLS
    elif security_raw == "reality":
        security = SecurityKind.REALITY
    elif security_raw == "none":
        security = SecurityKind.NONE
    else:
        security = default_security

    reality = None
    if security == SecurityKind.REALITY:
        reality = RealitySettings(
            public_key=q.get("pbk", ""),
            short_id=q.get("sid", ""),
            spider_x=q.get("spx", ""),
        )

    return TlsSettings(
        security=security,
        sni=q.get("sni", ""),
        alpn=split_alpn(q.get("alpn")),
        fingerprint=q.get("fp", ""),
        allow_insecure=truthy(q.get("allowInsecure") or q.get("insecure")),
        reality=reality,
    )


def tls_query_params(tls: TlsSettings) -> dict[str, str]:
    params: dict[str, str] = {}
    if tls.security != SecurityKind.NONE:
        params["security"] = tls.security.value
    if tls.sni:
        params["sni"] = tls.sni
    if tls.fingerprint:
        params["fp"] = tls.fingerprint
    if tls.alpn:
        params["alpn"] = ",".join(tls.alpn)
    if tls.allow_insecure:
        params["allowInsecure"] = "1"
    if tls.reality:
        if tls.reality.public_key:
            params["pbk"] = tls.reality.public_key
        if tls.reality.short_id:
            params["sid"] = tls.reality.short_id
        if tls.reality.spider_x:
            params["spx"] = tls.reality.spider_x
    return params
