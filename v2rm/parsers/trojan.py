from __future__ import annotations

from urllib.parse import quote

from v2rm.errors import ParseError
from v2rm.models.enums import Protocol, SecurityKind
from v2rm.models.profile import Profile
from v2rm.parsers import links

SCHEME = "trojan"


def parse(link: str) -> Profile:
    if not link.startswith("trojan://"):
        raise ParseError("Not a trojan:// link")
    parsed = links.split_uri(link)
    password = links.userinfo(parsed)
    if not password:
        raise ParseError("trojan link is missing the password")
    server, port = links.host_and_port(parsed, link)
    q = links.query_dict(parsed)

    return Profile(
        name=links.remark(parsed, f"{server}:{port}"),
        protocol=Protocol.TROJAN,
        server=server,
        port=port,
        raw_link=link,
        password=password,
        flow=q.get("flow", ""),
        transport=links.parse_transport(q),
        tls=links.parse_tls(q, default_security=SecurityKind.TLS),
    )


def to_link(profile: Profile) -> str:
    params = {}
    params.update(links.transport_query_params(profile.transport))
    params.update(links.tls_query_params(profile.tls))
    if profile.flow:
        params["flow"] = profile.flow
    return links.build_link(
        SCHEME, quote(profile.password, safe=""), profile.server, profile.port, params, profile.name
    )
