from __future__ import annotations

from urllib.parse import quote

from v2rm.errors import ParseError
from v2rm.models.enums import Protocol
from v2rm.models.profile import Profile
from v2rm.parsers import links

SCHEME = "ss"


def parse(link: str) -> Profile:
    if not link.startswith("ss://"):
        raise ParseError("Not a ss:// link")
    parsed = links.split_uri(link)

    body = link[len("ss://") :]
    body, _, _fragment = body.partition("#")
    body, _, _query = body.partition("?")

    if "@" in body:
        # SIP002: base64(method:password)@host:port
        userinfo_part, _, hostport = body.rpartition("@")
        decoded = links.b64_decode_text(userinfo_part)
        method, sep, password = decoded.partition(":")
        if not sep:
            raise ParseError("ss:// userinfo did not decode to 'method:password'")
        host, port = links.split_host_port(hostport)
    else:
        # Legacy: base64(method:password@host:port)
        decoded = links.b64_decode_text(body)
        creds, sep, hostport = decoded.rpartition("@")
        if not sep:
            raise ParseError("Legacy ss:// payload did not decode to 'method:password@host:port'")
        method, sep2, password = creds.partition(":")
        if not sep2:
            raise ParseError("ss:// credentials did not decode to 'method:password'")
        host, port = links.split_host_port(hostport)

    return Profile(
        name=links.remark(parsed, f"{host}:{port}"),
        protocol=Protocol.SHADOWSOCKS,
        server=host,
        port=port,
        raw_link=link,
        password=password,
        method=method,
    )


def to_link(profile: Profile) -> str:
    userinfo_part = links.b64_encode_urlsafe(f"{profile.method}:{profile.password}")
    host_part = f"[{profile.server}]" if ":" in profile.server else profile.server
    frag = quote(profile.name)
    return f"ss://{userinfo_part}@{host_part}:{profile.port}#{frag}"
