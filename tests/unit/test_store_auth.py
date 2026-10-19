from __future__ import annotations

import json
import os
import stat

import pytest

from v2rm.errors import V2rmError
from v2rm.models.auth import MAX_CREDENTIAL_BYTES, ProxyAuth
from v2rm.store import paths
from v2rm.store.auth import AuthStore


def test_nothing_saved_means_no_login():
    assert AuthStore().load() is None


def test_save_and_load_roundtrip():
    AuthStore().save(ProxyAuth("demo", "p@ss:word"))
    assert AuthStore().load() == ProxyAuth("demo", "p@ss:word")


def test_saving_again_replaces_the_login():
    store = AuthStore()
    store.save(ProxyAuth("a", "1"))
    store.save(ProxyAuth("b", "2"))
    assert store.load() == ProxyAuth("b", "2")


def test_clear_removes_it_and_reports_whether_there_was_one():
    store = AuthStore()
    assert store.clear() is False
    store.save(ProxyAuth("a", "1"))
    assert store.clear() is True
    assert store.load() is None
    assert not paths.auth_file().exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_the_file_is_readable_by_its_owner_only():
    AuthStore().save(ProxyAuth("demo", "secret"))
    assert stat.S_IMODE(paths.auth_file().stat().st_mode) == 0o600


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_the_mode_is_tightened_even_if_the_file_already_existed_loosely():
    paths.auth_file().parent.mkdir(parents=True, exist_ok=True)
    paths.auth_file().write_text(json.dumps({"user": "x", "password": "y"}))
    os.chmod(paths.auth_file(), 0o644)
    AuthStore().save(ProxyAuth("demo", "secret"))
    assert stat.S_IMODE(paths.auth_file().stat().st_mode) == 0o600


def test_the_login_lives_in_its_own_file_not_in_state_json():
    from v2rm.store.state import AppStateStore

    AuthStore().save(ProxyAuth("demo", "secret-value"))
    state_store = AppStateStore()
    state_store.save(state_store.load())
    assert "secret-value" not in paths.state_file().read_text(encoding="utf-8")
    assert paths.auth_file() != paths.state_file()


@pytest.mark.parametrize(
    "content",
    ["{not json", "[]", '"a string"', "{}", '{"user": "demo"}', '{"user": "", "password": "x"}',
     '{"user": "demo", "password": ""}', '{"user": 5, "password": "x"}', ""],
    ids=["garbage", "list", "string", "empty-object", "no-password", "empty-user", "empty-password", "wrong-type", "empty-file"],
)
def test_a_damaged_file_fails_loudly_instead_of_meaning_no_login(content):
    paths.auth_file().parent.mkdir(parents=True, exist_ok=True)
    paths.auth_file().write_text(content)
    with pytest.raises(V2rmError) as err:
        AuthStore().load()
    assert "v2rm port set --auth USER:PASS" in str(err.value)
    assert "--no-auth" in str(err.value)


def test_a_damaged_file_can_still_be_cleared_or_replaced():
    paths.auth_file().parent.mkdir(parents=True, exist_ok=True)
    paths.auth_file().write_text("{broken")
    assert AuthStore().clear() is True

    paths.auth_file().write_text("{broken")
    AuthStore().save(ProxyAuth("demo", "fresh"))
    assert AuthStore().load() == ProxyAuth("demo", "fresh")


# ---- ProxyAuth ------------------------------------------------------------------------------------------


def test_parse_splits_at_the_first_colon():
    assert ProxyAuth.parse("demo:pw") == ProxyAuth("demo", "pw")
    assert ProxyAuth.parse("demo:a:b:c") == ProxyAuth("demo", "a:b:c")
    assert ProxyAuth.parse("démo:pässwörd") == ProxyAuth("démo", "pässwörd")


@pytest.mark.parametrize("value", ["", "nocolon", "user:", ":pass", ":"])
def test_parse_requires_both_parts(value):
    with pytest.raises(V2rmError, match="USER:PASS"):
        ProxyAuth.parse(value)


def test_parse_rejects_control_characters():
    for value in ("us\ner:pw", "user:p\tw", "user:pw\x00", "user\r:pw", "user:pw\x7f"):
        with pytest.raises(V2rmError, match="control characters"):
            ProxyAuth.parse(value)


def test_parse_limits_each_part_to_what_socks5_can_carry():
    ProxyAuth.parse("u" * MAX_CREDENTIAL_BYTES + ":" + "p" * MAX_CREDENTIAL_BYTES)
    with pytest.raises(V2rmError, match="user name is too long"):
        ProxyAuth.parse("u" * (MAX_CREDENTIAL_BYTES + 1) + ":pw")
    with pytest.raises(V2rmError, match="password is too long"):
        ProxyAuth.parse("user:" + "p" * (MAX_CREDENTIAL_BYTES + 1))
    # The limit is in bytes, not characters.
    with pytest.raises(V2rmError, match="too long"):
        ProxyAuth.parse("user:" + "é" * 128)


def test_userinfo_percent_encodes_everything_that_could_break_a_url():
    assert ProxyAuth("us er", "p@ss:w/rd?#[]").userinfo() == "us%20er:p%40ss%3Aw%2Frd%3F%23%5B%5D"
    assert ProxyAuth("plain-name_1.x~", "pw").userinfo() == "plain-name_1.x~:pw"
