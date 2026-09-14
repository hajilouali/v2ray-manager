from __future__ import annotations

from urllib.parse import quote

from v2rm.errors import ParseError
from v2rm.models.enums import Protocol, SecurityKind
from v2rm.models.profile import Profile, TlsSettings
from v2rm.parsers import links

SCHEME = "tuic"

_EXTRA_FLAGS = ("udp_relay_mode", "reduce_rtt", "disable_sni")


def parse(link: str) -> Profile:
    if not link.startswith("tuic://"):
        raise ParseError("Not a tuic:// link")
    parsed = links.split_uri(link)
    uuid = links.userinfo(parsed)
    password = links.userinfo_password(parsed)
    if not uuid:
        raise ParseError("tuic link is missing the uuid")
    server, port = links.host_and_port(parsed, link)
    q = links.query_dict(parsed)

    extra = {key: q[key] for key in _EXTRA_FLAGS if q.get(key)}

    return Profile(
        name=links.remark(parsed, f"{server}:{port}"),
        protocol=Protocol.TUIC,
        server=server,
        port=port,
        raw_link=link,
        uuid=uuid,
        password=password,
        congestion_control=q.get("congestion_control", ""),
        tls=TlsSettings(
            security=SecurityKind.TLS,
            sni=q.get("sni", ""),
            alpn=links.split_alpn(q.get("alpn")),
            allow_insecure=links.truthy(q.get("allow_insecure") or q.get("insecure")),
        ),
        extra=extra,
    )


def to_link(profile: Profile) -> str:
    params = {}
    if profile.congestion_control:
        params["congestion_control"] = profile.congestion_control
    if profile.tls.sni:
        params["sni"] = profile.tls.sni
    if profile.tls.alpn:
        params["alpn"] = ",".join(profile.tls.alpn)
    if profile.tls.allow_insecure:
        params["allow_insecure"] = "1"
    for key in _EXTRA_FLAGS:
        if profile.extra.get(key):
            params[key] = profile.extra[key]
    userinfo_part = f"{quote(profile.uuid, safe='')}:{quote(profile.password, safe='')}"
    return links.build_link(SCHEME, userinfo_part, profile.server, profile.port, params, profile.name)
