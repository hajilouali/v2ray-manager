from __future__ import annotations

from v2rm.errors import ParseError
from v2rm.models.enums import Protocol
from v2rm.models.profile import Profile
from v2rm.parsers import hysteria2, shadowsocks, trojan, tuic, vless, vmess

_SCHEME_PARSERS = {
    "vmess": vmess.parse,
    "vless": vless.parse,
    "trojan": trojan.parse,
    "ss": shadowsocks.parse,
    "hysteria2": hysteria2.parse,
    "hy2": hysteria2.parse,
    "tuic": tuic.parse,
}

_PROTOCOL_ENCODERS = {
    Protocol.VMESS: vmess.to_link,
    Protocol.VLESS: vless.to_link,
    Protocol.TROJAN: trojan.to_link,
    Protocol.SHADOWSOCKS: shadowsocks.to_link,
    Protocol.HYSTERIA2: hysteria2.to_link,
    Protocol.TUIC: tuic.to_link,
}

SUPPORTED_SCHEMES = tuple(_SCHEME_PARSERS)


def parse_link(link: str) -> Profile:
    link = link.strip()
    if "://" not in link:
        raise ParseError(f"Not a recognized share link: '{link[:50]}'")
    scheme = link.split("://", 1)[0].lower()
    parser = _SCHEME_PARSERS.get(scheme)
    if parser is None:
        raise ParseError(f"Unsupported link scheme '{scheme}://'")
    return parser(link)


def parse_links(text: str) -> tuple[list[Profile], list[tuple[str, str]]]:
    """Parse one link per non-empty, non-comment line.

    Returns (profiles, errors) -- errors is a list of (line, message) for
    lines that failed to parse, so callers can report partial success
    instead of aborting on the first bad line. Also used for base64/plain
    -list subscription bodies, which have the same shape.
    """
    profiles: list[Profile] = []
    errors: list[tuple[str, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            profiles.append(parse_link(line))
        except ParseError as exc:
            errors.append((line, str(exc)))
    return profiles, errors


def to_link(profile: Profile) -> str:
    encoder = _PROTOCOL_ENCODERS.get(profile.protocol)
    if encoder is None:
        raise ParseError(f"No link encoder for protocol '{profile.protocol.value}'")
    return encoder(profile)
