"""Upgrade profiles that an older v2rm stored.

Older parsers dropped link parameters such as `cs`, `fm`, `ech`, `extra`,
`mode`, `headers` and VLESS `encryption`. Profile.identity_key() now includes
a hash of those, so an un-upgraded profile would never match the freshly
parsed copy of itself on the next subscription refresh -- every stored
profile would look "gone" and every fetched one "new", losing profile ids
(including the active one). Re-deriving the dropped fields from the stored
share link on load avoids that.
"""

from __future__ import annotations

from v2rm.errors import ParseError
from v2rm.models.enums import Protocol
from v2rm.models.profile import SCHEMA_VERSION, Profile
from v2rm.parsers import parse_link

_LINK_PROTOCOLS = {Protocol.VLESS, Protocol.TROJAN, Protocol.VMESS}


def upgrade_profile(profile: Profile) -> Profile:
    """Bring a stored profile up to the current schema, in memory.

    Only fills fields the old parsers dropped; it never overwrites a stored
    value, so edits the user made with `profile edit` survive. It isn't
    persisted here (a read shouldn't write): the upgraded profile is saved
    the next time it's updated, and re-derived until then (cheap)."""
    if profile.schema >= SCHEMA_VERSION:
        return profile

    if profile.raw_link and profile.protocol in _LINK_PROTOCOLS:
        try:
            fresh = parse_link(profile.raw_link)
        except (ParseError, ValueError, KeyError, TypeError):
            fresh = None
        if fresh is not None and fresh.protocol == profile.protocol:
            _adopt_dropped_fields(profile, fresh)

    profile.schema = SCHEMA_VERSION
    return profile


def _adopt_dropped_fields(profile: Profile, fresh: Profile) -> None:
    if not profile.tls.cipher_suites:
        profile.tls.cipher_suites = fresh.tls.cipher_suites
    if not profile.tls.ech_config_list:
        profile.tls.ech_config_list = fresh.tls.ech_config_list
    if not profile.transport.finalmask:
        profile.transport.finalmask = fresh.transport.finalmask
    if not profile.transport.mode:
        profile.transport.mode = fresh.transport.mode
    if not profile.transport.xhttp_extra:
        profile.transport.xhttp_extra = fresh.transport.xhttp_extra
    if not profile.transport.headers:
        profile.transport.headers = dict(fresh.transport.headers)
    if not profile.encryption:
        profile.encryption = fresh.encryption
    if not profile.packet_encoding:
        profile.packet_encoding = fresh.packet_encoding
    for key, value in fresh.extra.items():
        profile.extra.setdefault(key, value)
