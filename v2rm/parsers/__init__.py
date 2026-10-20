from __future__ import annotations

from v2rm.errors import ParseError
from v2rm.models.enums import Protocol
from v2rm.models.profile import Profile
from v2rm.parsers import aether, hysteria2, masque, shadowsocks, trojan, tuic, vless, vmess

_SCHEME_PARSERS = {
    "aether": aether.parse,
    "vmess": vmess.parse,
    "vless": vless.parse,
    "trojan": trojan.parse,
    "ss": shadowsocks.parse,
    "hysteria2": hysteria2.parse,
    "hy2": hysteria2.parse,
    "tuic": tuic.parse,
    "masque": masque.parse,
}

_PROTOCOL_ENCODERS = {
    Protocol.VMESS: vmess.to_link,
    Protocol.VLESS: vless.to_link,
    Protocol.TROJAN: trojan.to_link,
    Protocol.SHADOWSOCKS: shadowsocks.to_link,
    Protocol.HYSTERIA2: hysteria2.to_link,
    Protocol.TUIC: tuic.to_link,
    Protocol.MASQUE: masque.to_link,
    Protocol.AETHER: aether.to_link,
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
    for line in text.lstrip("﻿").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            profiles.append(parse_link(line))
        except (ParseError, ValueError, KeyError, TypeError) as exc:
            # One malformed link in a several-hundred-link subscription must
            # be reported, not abort the whole import.
            errors.append((line, str(exc)))
    return profiles, errors


def to_link(profile: Profile) -> str:
    if profile.protocol == Protocol.RAW_XRAY:
        raise ParseError(
            "Raw Xray profiles are complete configs, not a server, so they have no share link. "
            "Use `v2rm profile show <id> --json` to print the config instead."
        )
    if profile.protocol == Protocol.CHAIN:
        raise ParseError(
            "A chain refers to profiles on this machine by id, so it has no share link. "
            "Share the profiles it uses, or use `v2rm export` / `v2rm import` to move everything."
        )
    encoder = _PROTOCOL_ENCODERS.get(profile.protocol)
    if encoder is None:
        raise ParseError(f"No link encoder for protocol '{profile.protocol.value}'")
    return encoder(profile)
