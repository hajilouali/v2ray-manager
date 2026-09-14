from __future__ import annotations

from urllib.parse import quote

from v2rm.errors import ParseError
from v2rm.models.enums import Protocol, SecurityKind
from v2rm.models.profile import Profile, TlsSettings
from v2rm.parsers import links

SCHEMES = ("hysteria2", "hy2")


def parse(link: str) -> Profile:
    scheme = link.split("://", 1)[0].lower() if "://" in link else ""
    if scheme not in SCHEMES:
        raise ParseError("Not a hysteria2:// or hy2:// link")
    parsed = links.split_uri(link)
    password = links.userinfo(parsed)
    if not password:
        raise ParseError("hysteria2 link is missing the password/auth")
    server, port = links.host_and_port(parsed, link)
    q = links.query_dict(parsed)

    extra: dict = {}
    if q.get("obfs"):
        extra["obfs"] = q["obfs"]
    if q.get("obfs-password"):
        extra["obfs_password"] = q["obfs-password"]
    if q.get("pinSHA256"):
        extra["pin_sha256"] = q["pinSHA256"]

    return Profile(
        name=links.remark(parsed, f"{server}:{port}"),
        protocol=Protocol.HYSTERIA2,
        server=server,
        port=port,
        raw_link=link,
        password=password,
        tls=TlsSettings(
            security=SecurityKind.TLS,
            sni=q.get("sni", ""),
            alpn=links.split_alpn(q.get("alpn")),
            allow_insecure=links.truthy(q.get("insecure")),
        ),
        extra=extra,
    )


def to_link(profile: Profile) -> str:
    params = {}
    if profile.tls.sni:
        params["sni"] = profile.tls.sni
    if profile.tls.allow_insecure:
        params["insecure"] = "1"
    if profile.tls.alpn:
        params["alpn"] = ",".join(profile.tls.alpn)
    if profile.extra.get("obfs"):
        params["obfs"] = profile.extra["obfs"]
    if profile.extra.get("obfs_password"):
        params["obfs-password"] = profile.extra["obfs_password"]
    return links.build_link(
        "hysteria2", quote(profile.password, safe=""), profile.server, profile.port, params, profile.name
    )
