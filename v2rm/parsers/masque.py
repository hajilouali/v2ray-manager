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
from urllib.parse import quote

from v2rm.errors import ParseError, ProfileValidationError
from v2rm.models.enums import Protocol, SecurityKind
from v2rm.models.profile import Profile, TlsSettings, TransportSettings
from v2rm.parsers import links

SCHEME = "masque"
DEFAULT_ALPN = ["h2"]

# Headers Xray-core's MasqueConfig.Build refuses (it sets/owns these itself).
_FORBIDDEN_HEADERS = {"host", "capsule-protocol"}


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

    for key in profile.transport.headers:
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
