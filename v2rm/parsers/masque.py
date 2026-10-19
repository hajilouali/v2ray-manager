"""MASQUE profiles and the `masque://` link scheme.

There is no ecosystem-standard share link for MASQUE; `masque://` is v2rm's
own convention:

    masque://[user:pass@]host:port?sni=&alpn=h2&fp=&path=&host=&headers=<json>&fm=<json>&dns=&warp=<json>#name

`headers`, `fm` and `warp` are URL-encoded JSON objects; `dns` is a comma
separated list of IPs (Xray's `remoteDNS`). `alpn` defaults to `h2`, i.e.
HTTP/2 mode: in Xray-core's MASQUE client, `h2` without `h3` selects HTTP/2
Extended CONNECT, anything else HTTP/3.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import quote, urlsplit

from v2rm.errors import ParseError, ProfileValidationError
from v2rm.models.enums import Protocol, SecurityKind
from v2rm.models.profile import Profile, TlsSettings, TransportSettings
from v2rm.parsers import links

SCHEME = "masque"
DEFAULT_ALPN = ["h2"]

# Headers Xray-core's MasqueConfig.Build refuses (it sets/owns these itself).
_FORBIDDEN_HEADERS = {"host", "capsule-protocol"}

# HTTP header field names are RFC 9110 "tokens".
_HEADER_NAME = re.compile(r"[A-Za-z0-9!#$%&'*+.^_`|~-]+")


def _strip_path_variables(path: str) -> str:
    """The `path` without the two URI-template variables Xray substitutes
    ({target} and {ipproto}); anything else in braces is an error upstream."""
    return path.replace("{target}", "").replace("{ipproto}", "")


def _is_plain_authority(host: str) -> bool:
    """Xray accepts `host` only if `https://<host>` parses back to exactly that
    host -- i.e. a bare host or host:port, with no path, query, userinfo or spaces."""
    try:
        parts = urlsplit("https://" + host)
        return parts.netloc == host and not (parts.path or parts.query or parts.fragment) and "@" not in host and " " not in host
    except ValueError:
        return False


def validate_masque(profile: Profile) -> None:
    """Mirror the checks Xray-core's MasqueConfig/MasqueClientConfig Build do,
    so a bad profile is rejected when it's added -- with a readable message --
    rather than as an engine start-up failure later."""
    user = str(profile.extra.get("user", ""))
    password = profile.password
    warp = profile.extra.get("warp")

    if not profile.server:
        raise ProfileValidationError("MASQUE profile needs a server")
    if not 1 <= profile.port <= 65535:
        raise ProfileValidationError(f"MASQUE profile has an invalid port: {profile.port}")

    if warp:
        if user or password:
            raise ProfileValidationError('MASQUE: "user"/"pass" can\'t be used together with "warp"')
        if not isinstance(warp, dict) or not all(warp.get(k) for k in ("privateKey", "publicKey", "address")):
            raise ProfileValidationError('MASQUE: "warp" needs privateKey, publicKey and address')

    if ":" in user:
        raise ProfileValidationError('MASQUE: "user" can\'t contain ":"')

    path = profile.transport.path
    if path and not path.startswith("/"):
        raise ProfileValidationError(f'MASQUE: "path" must start with "/", got {path!r}')
    if path and ("{" in _strip_path_variables(path) or "}" in _strip_path_variables(path)):
        raise ProfileValidationError(
            f'MASQUE: invalid "path" {path!r}, only the variables {{target}} and {{ipproto}} are supported'
        )

    host = profile.transport.host
    if host and not _is_plain_authority(host):
        raise ProfileValidationError(f'MASQUE: invalid "host" {host!r}')

    for key, value in profile.transport.headers.items():
        if not _HEADER_NAME.fullmatch(key) or any(ch in value for ch in "\r\n\x00"):
            raise ProfileValidationError(f'MASQUE: invalid header in "headers": "{key}"')
        lowered = key.lower()
        if lowered in _FORBIDDEN_HEADERS:
            raise ProfileValidationError(f'MASQUE: "headers" can\'t contain "{key}"')
        if lowered == "authorization" and (user or password):
            raise ProfileValidationError('MASQUE: "headers" can\'t contain "Authorization" when user/pass is set')

    for addr in profile.extra.get("remote_dns", []) or []:
        try:
            ipaddress.ip_address(addr)
        except ValueError as exc:
            raise ProfileValidationError(f'MASQUE: remote DNS "{addr}" is not an IP address') from exc


def parse(link: str) -> Profile:
    if not link.startswith("masque://"):
        raise ParseError("Not a masque:// link")
    parsed = links.split_uri(link)
    user = links.userinfo(parsed)
    password = links.userinfo_password(parsed)
    server, port = links.host_and_port(parsed, link)
    q = links.query_dict(parsed)

    extra: dict = {}
    if user:
        extra["user"] = user
    warp = links.parse_json_object(q.get("warp"), "warp")
    if warp:
        extra["warp"] = warp
    dns = [d.strip() for d in (q.get("dns") or "").split(",") if d.strip()]
    if dns:
        extra["remote_dns"] = dns

    profile = Profile(
        name=links.remark(parsed, f"{server}:{port}"),
        protocol=Protocol.MASQUE,
        server=server,
        port=port,
        raw_link=link,
        password=password,
        transport=TransportSettings(
            path=q.get("path", ""),
            host=q.get("host", ""),
            headers=links.parse_headers(q.get("headers")),
            finalmask=links.parse_json_object(q.get("fm"), "fm"),
        ),
        tls=TlsSettings(
            security=SecurityKind.TLS,
            sni=q.get("sni", ""),
            alpn=links.split_alpn(q.get("alpn")) or list(DEFAULT_ALPN),
            fingerprint=q.get("fp", ""),
        ),
        extra=extra,
    )
    try:
        validate_masque(profile)
    except ProfileValidationError as exc:
        raise ParseError(str(exc)) from exc
    return profile


def to_link(profile: Profile) -> str:
    user = str(profile.extra.get("user", ""))
    userinfo = ""
    if user or profile.password:
        userinfo = quote(user, safe="")
        if profile.password:
            userinfo += ":" + quote(profile.password, safe="")

    params: dict[str, str] = {}
    if profile.tls.sni:
        params["sni"] = profile.tls.sni
    params["alpn"] = ",".join(profile.tls.alpn or DEFAULT_ALPN)
    if profile.tls.fingerprint:
        params["fp"] = profile.tls.fingerprint
    if profile.transport.path:
        params["path"] = profile.transport.path
    if profile.transport.host:
        params["host"] = profile.transport.host
    if profile.transport.headers:
        params["headers"] = links.compact_json(profile.transport.headers)
    if profile.transport.finalmask:
        params["fm"] = links.compact_json(profile.transport.finalmask)
    if profile.extra.get("remote_dns"):
        params["dns"] = ",".join(profile.extra["remote_dns"])
    if profile.extra.get("warp"):
        params["warp"] = links.compact_json(profile.extra["warp"])
    return links.build_link(SCHEME, userinfo, profile.server, profile.port, params, profile.name)


def build_profile(
    *,
    server: str,
    port: int,
    sni: str,
    alpn: list[str] | None = None,
    user: str = "",
    password: str = "",
    path: str = "",
    host: str = "",
    headers: dict[str, str] | None = None,
    fingerprint: str = "",
    name: str = "",
) -> Profile:
    """A MASQUE profile from individual fields (`v2rm add masque ...`, the menu)
    -- the same shape `parse()` produces from a link, validated the same way,
    with its `masque://` link recorded so `profile show --link` round-trips."""
    profile = Profile(
        name=name or f"{server}:{port}",
        protocol=Protocol.MASQUE,
        server=server,
        port=port,
        password=password,
        transport=TransportSettings(path=path, host=host, headers=dict(headers or {})),
        tls=TlsSettings(
            security=SecurityKind.TLS,
            sni=sni,
            alpn=list(alpn or DEFAULT_ALPN),
            fingerprint=fingerprint,
        ),
        extra={"user": user} if user else {},
    )
    validate_masque(profile)
    profile.raw_link = to_link(profile)
    return profile
