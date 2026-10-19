from __future__ import annotations

import json

from tests.helpers import free_links
from v2rm.models.profile import SCHEMA_VERSION, Profile
from v2rm.parsers import parse_link
from v2rm.parsers.migrate import upgrade_profile
from v2rm.store import paths
from v2rm.store.profiles import ProfileStore

LINKS = free_links()

_DROPPED_BY_OLD_PARSERS = ("cipher_suites", "ech_config_list")


def as_stored_by_the_previous_version(profile: Profile) -> dict:
    """What an older v2rm wrote: none of the new keys, no schema marker."""
    d = profile.to_dict()
    for key in _DROPPED_BY_OLD_PARSERS:
        d["tls"].pop(key)
    for key in ("mode", "xhttp_extra", "finalmask"):
        d["transport"].pop(key)
    d["transport"]["headers"] = {}
    for key in ("encryption", "packet_encoding", "raw_config", "schema"):
        d.pop(key)
    d["extra"] = {}
    return d


def test_old_profile_regains_the_parameters_the_old_parser_dropped():
    fresh = parse_link(LINKS[0])
    old = Profile.from_dict(as_stored_by_the_previous_version(fresh))
    assert old.schema == 1 and not old.tls.cipher_suites and not old.transport.finalmask

    upgraded = upgrade_profile(old)

    assert upgraded.schema == SCHEMA_VERSION
    assert upgraded.tls.cipher_suites == fresh.tls.cipher_suites
    assert upgraded.transport.finalmask == fresh.transport.finalmask
    # So it matches its own freshly parsed copy on the next subscription refresh:
    assert upgraded.identity_key() == fresh.identity_key()


def test_without_the_upgrade_an_old_profile_would_look_like_a_different_node():
    fresh = parse_link(LINKS[0])
    old = Profile.from_dict(as_stored_by_the_previous_version(fresh))
    assert old.identity_key() != fresh.identity_key()


def test_user_edits_are_never_overwritten_by_the_upgrade():
    fresh = parse_link(LINKS[0])
    d = as_stored_by_the_previous_version(fresh)
    d["server"] = "edited.example.com"
    d["transport"]["path"] = "/edited"
    old = Profile.from_dict(d)

    upgraded = upgrade_profile(old)

    assert upgraded.server == "edited.example.com"
    assert upgraded.transport.path == "/edited"
    assert upgraded.tls.cipher_suites == fresh.tls.cipher_suites  # the dropped bits still come back


def test_mlkem_encryption_and_headers_and_xhttp_are_recovered():
    for link in LINKS:
        fresh = parse_link(link)
        if not (fresh.encryption or fresh.transport.headers or fresh.transport.xhttp_extra):
            continue
        old = Profile.from_dict(as_stored_by_the_previous_version(fresh))
        up = upgrade_profile(old)
        assert up.encryption == fresh.encryption
        assert up.transport.headers == fresh.transport.headers
        assert up.transport.xhttp_extra == fresh.transport.xhttp_extra
        assert up.transport.mode == fresh.transport.mode
        assert up.identity_key() == fresh.identity_key()


def test_profile_without_a_stored_link_just_gets_the_schema_bump():
    d = as_stored_by_the_previous_version(parse_link(LINKS[0]))
    d["raw_link"] = None
    up = upgrade_profile(Profile.from_dict(d))
    assert up.schema == SCHEMA_VERSION
    assert not up.tls.cipher_suites


def test_an_unparseable_stored_link_does_not_break_loading():
    d = as_stored_by_the_previous_version(parse_link(LINKS[0]))
    d["raw_link"] = "vless://u@h.example.com:443?fm=%7Bbroken"
    up = upgrade_profile(Profile.from_dict(d))
    assert up.schema == SCHEMA_VERSION


def test_current_schema_profiles_are_returned_untouched():
    p = parse_link(LINKS[0])
    assert p.schema == SCHEMA_VERSION
    assert upgrade_profile(p) is p


def test_store_upgrades_on_load_without_writing_and_persists_when_updated():
    fresh = parse_link(LINKS[0])
    stored = as_stored_by_the_previous_version(fresh)
    store = ProfileStore()
    store._save_raw([stored])
    before = paths.profiles_file().read_text(encoding="utf-8")

    (loaded,) = store.list()
    assert loaded.schema == SCHEMA_VERSION
    assert loaded.identity_key() == fresh.identity_key()
    assert store.get(loaded.id).tls.cipher_suites == fresh.tls.cipher_suites

    # Reading is pure: the file on disk is still the old-format one...
    assert paths.profiles_file().read_text(encoding="utf-8") == before
    assert "schema" not in json.loads(before)["profiles"][0]

    # ...and it becomes schema 2 the next time the profile is written.
    store.update_many([loaded])
    assert json.loads(paths.profiles_file().read_text(encoding="utf-8"))["profiles"][0]["schema"] == SCHEMA_VERSION
