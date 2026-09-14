from __future__ import annotations

from urllib.parse import quote

from v2rm.errors import ParseError
from v2rm.models.enums import Protocol, SecurityKind
from v2rm.models.profile import Profile
from v2rm.parsers import links

SCHEME = "vless"


def parse(link: str) -> Profile:
    if not link.startswith("vless://"):
        raise ParseError("Not a vless:// link")
    parsed = links.split_uri(link)
    uuid = links.userinfo(parsed)
    if not uuid:
        raise ParseError("vless link is missing the uuid")
    server, port = links.host_and_port(parsed, link)
    q = links.query_dict(parsed)

    extra: dict = {}
    header_type = q.get("headerType", "")
    if header_type and header_type != "none":
        extra["header_type"] = header_type

    return Profile(
        name=links.remark(parsed, f"{server}:{port}"),
        protocol=Protocol.VLESS,
        server=server,
        port=port,
        raw_link=link,
        uuid=uuid,
        flow=q.get("flow", ""),
        transport=links.parse_transport(q),
        tls=links.parse_tls(q, default_security=SecurityKind.NONE),
        extra=extra,
    )


def to_link(profile: Profile) -> str:
    params = {"encryption": "none"}
    params.update(links.transport_query_params(profile.transport))
    params.update(links.tls_query_params(profile.tls))
    if profile.flow:
        params["flow"] = profile.flow
    if profile.extra.get("header_type"):
        params["headerType"] = profile.extra["header_type"]
    return links.build_link(
        SCHEME, quote(profile.uuid, safe=""), profile.server, profile.port, params, profile.name
    )
