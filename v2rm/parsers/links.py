from __future__ import annotations

import base64
import binascii
import json
from typing import Any
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


def compact_json(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def parse_json_object(value: str | None, param: str) -> dict[str, Any]:
    """A JSON-object-valued query parameter (fm, extra, warp, ...). Empty ->
    {}. Invalid JSON, or a JSON value that isn't an object, is reported
    rather than silently dropped."""
    if not value or not value.strip():
        return {}
    try:
        data = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ParseError(f"Parameter '{param}' is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ParseError(f"Parameter '{param}' must be a JSON object")
    return data


def parse_headers(value: str | None) -> dict[str, str]:
    """`headers` as a JSON object (`{"Host":"x"}`) or as a `k:v` list
    separated by commas/semicolons/newlines (`Host:x,X-Y:z`)."""
    if not value or not value.strip():
        return {}
    text = value.strip()
    if text.startswith("{"):
        data = parse_json_object(text, "headers")
        return {str(k): str(v) for k, v in data.items()}
    headers: dict[str, str] = {}
    for part in text.replace(";", ",").replace("\n", ",").split(","):
        key, sep, val = part.partition(":")
        key = key.strip()
        if not sep or not key:
            raise ParseError(f"Parameter 'headers' has an entry that isn't 'key:value': {part.strip()!r}")
        headers[key] = val.strip()
    return headers


def collect_extra(q: dict[str, str]) -> dict[str, Any]:
    """Long-tail link parameters kept on Profile.extra: the legacy `headerType`
    and the legacy sockopt `fragment` (which has no faithful finalmask
    equivalent, so it's preserved verbatim and flagged at connect time)."""
    extra: dict[str, Any] = {}
    header_type = q.get("headerType", "")
    if header_type and header_type != "none":
        extra["header_type"] = header_type
    if q.get("fragment"):
        extra["fragment"] = q["fragment"]
    return extra


def packet_encoding_of(q: dict[str, str]) -> str:
    return q.get("packetEncoding") or q.get("packet-encoding") or ""


def build_link(scheme: str, userinfo_part: str, host: str, port: int, params: dict[str, str], name: str) -> str:
    query = urlencode(params)
    frag = quote(name)
    host_part = f"[{host}]" if ":" in host else host
    suffix = f"?{query}" if query else ""
    auth = f"{userinfo_part}@" if userinfo_part else ""
    return f"{scheme}://{auth}{host_part}:{port}{suffix}#{frag}"


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
        headers=parse_headers(q.get("headers")),
        mode=q.get("mode", ""),
        xhttp_extra=parse_json_object(q.get("extra"), "extra"),
        finalmask=parse_json_object(q.get("fm"), "fm"),
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
    if transport.mode:
        params["mode"] = transport.mode
    if transport.xhttp_extra:
        params["extra"] = compact_json(transport.xhttp_extra)
    if transport.finalmask:
        params["fm"] = compact_json(transport.finalmask)
    if transport.headers:
        params["headers"] = compact_json(transport.headers)
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
        # Passed through verbatim (fp=unsafe included) -- no whitelist; the
        # engine is the authority on which fingerprints it knows.
        fingerprint=q.get("fp", ""),
        allow_insecure=truthy(q.get("allowInsecure") or q.get("insecure")),
        reality=reality,
        cipher_suites=q.get("cs", ""),
        ech_config_list=q.get("ech") or q.get("echConfigList") or q.get("echcl") or "",
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
    if tls.cipher_suites:
        params["cs"] = tls.cipher_suites
    if tls.ech_config_list:
        params["ech"] = tls.ech_config_list
    if tls.reality:
        if tls.reality.public_key:
            params["pbk"] = tls.reality.public_key
        if tls.reality.short_id:
            params["sid"] = tls.reality.short_id
        if tls.reality.spider_x:
            params["spx"] = tls.reality.spider_x
    return params
