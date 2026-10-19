from __future__ import annotations

from tests.helpers import free_links
from v2rm.models.enums import Protocol
from v2rm.models.profile import Profile
from v2rm.parsers import parse_link
from v2rm.subscription.sync import diff_subscription_members


def make(name: str, server: str, port: int = 443, uuid: str = "u1") -> Profile:
    return Profile(name=name, protocol=Protocol.VLESS, server=server, port=port, uuid=uuid)


def raw(remarks: str | None, body: str = "x") -> Profile:
    cfg: dict = {"outbounds": [{"tag": body}]}
    if remarks:
        cfg["remarks"] = remarks
    return Profile(name=remarks or "raw", protocol=Protocol.RAW_XRAY, raw_config=cfg)


def test_diff_adds_new_profiles():
    result = diff_subscription_members([], [make("A", "a.example.com")])
    assert len(result.added) == 1
    assert not result.updated
    assert not result.removed_ids


def test_diff_matches_by_identity_preserves_id_across_rename():
    old = make("OldName", "a.example.com")
    new = make("NewName", "a.example.com")  # same identity key, renamed upstream

    result = diff_subscription_members([old], [new])
    assert not result.added
    assert not result.removed_ids
    assert len(result.updated) == 1
    assert result.updated[0].id == old.id
    assert result.updated[0].name == "NewName"


def test_diff_removes_missing_profiles():
    old = make("Gone", "gone.example.com")
    result = diff_subscription_members([old], [])
    assert result.removed_ids == [old.id]


def test_diff_mixed_add_update_remove():
    keep = make("Keep", "keep.example.com")
    gone = make("Gone", "gone.example.com")
    renamed = make("Old name", "renamed.example.com")
    result = diff_subscription_members(
        [keep, gone, renamed],
        [make("Keep", "keep.example.com"), make("New", "new.example.com"), make("New name", "renamed.example.com")],
    )

    assert [p.name for p in result.added] == ["New"]
    assert [p.id for p in result.updated] == [renamed.id]  # only the one that really changed
    assert set(result.kept_ids) == {keep.id, renamed.id}
    assert result.unchanged == 1
    assert result.removed_ids == [gone.id]


def test_an_unchanged_refresh_reports_nothing_to_write():
    existing = [make("A", "a.example.com"), make("B", "b.example.com")]
    fetched = [make("A", "a.example.com"), make("B", "b.example.com")]
    result = diff_subscription_members(existing, fetched)
    assert not result.added and not result.updated and not result.removed_ids
    assert result.unchanged == 2


def test_diff_different_uuid_is_treated_as_a_different_profile():
    old = make("Same server, different key", "a.example.com", uuid="u1")
    new = make("Same server, different key", "a.example.com", uuid="u2")
    result = diff_subscription_members([old], [new])
    assert len(result.added) == 1
    assert result.removed_ids == [old.id]
    assert not result.updated


def test_duplicate_keys_are_matched_one_to_one_not_collapsed():
    # Real lists carry the same node several times under different labels
    # (identical parameters, different names). Three fetched copies must stay
    # three profiles: nothing wrongly removed, nothing re-added.
    existing = [make("copy one", "dup.example.com"), make("copy two", "dup.example.com"), make("copy three", "dup.example.com")]
    fetched = [make("copy one", "dup.example.com"), make("copy two", "dup.example.com"), make("copy three", "dup.example.com")]
    result = diff_subscription_members(existing, fetched)
    assert not result.added and not result.updated and not result.removed_ids
    assert sorted(result.kept_ids) == sorted(p.id for p in existing)


def test_duplicates_prefer_the_same_name_even_when_the_order_changes():
    a, b = make("alpha", "dup.example.com"), make("beta", "dup.example.com")
    result = diff_subscription_members([a, b], [make("beta", "dup.example.com"), make("alpha", "dup.example.com")])
    assert not result.updated  # beta matched beta, alpha matched alpha: no id/name swap
    assert set(result.kept_ids) == {a.id, b.id}


def test_fewer_duplicates_fetched_than_stored_removes_the_extra_one():
    existing = [make("x", "dup.example.com"), make("y", "dup.example.com")]
    result = diff_subscription_members(existing, [make("x", "dup.example.com")])
    assert len(result.kept_ids) == 1
    assert len(result.removed_ids) == 1
    assert not result.added


def test_more_duplicates_fetched_than_stored_adds_the_extra_one():
    result = diff_subscription_members(
        [make("x", "dup.example.com")], [make("x", "dup.example.com"), make("y", "dup.example.com")]
    )
    assert [p.name for p in result.added] == ["y"]
    assert not result.removed_ids


def test_raw_profile_with_same_remarks_but_new_body_updates_in_place():
    old = raw("Serverless-v52-fragA", body="old")
    new = raw("Serverless-v52-fragA", body="new")
    result = diff_subscription_members([old], [new])
    assert not result.added and not result.removed_ids
    assert len(result.updated) == 1
    assert result.updated[0].id == old.id
    assert result.updated[0].raw_config["outbounds"][0]["tag"] == "new"


def test_raw_profile_with_changed_remarks_is_a_different_profile():
    result = diff_subscription_members([raw("fragA")], [raw("fragB")])
    assert [p.name for p in result.added] == ["fragB"]
    assert len(result.removed_ids) == 1


def test_raw_profile_without_remarks_matches_by_content():
    same = diff_subscription_members([raw(None, "a")], [raw(None, "a")])
    assert not same.added and not same.removed_ids and same.unchanged == 1
    changed = diff_subscription_members([raw(None, "a")], [raw(None, "b")])
    assert len(changed.added) == 1 and len(changed.removed_ids) == 1


def test_real_sample_refresh_is_a_noop_and_keeps_all_ids():
    links = free_links()
    existing = [parse_link(link) for link in links]
    fetched = [parse_link(link) for link in links]
    result = diff_subscription_members(existing, fetched)
    assert not result.added and not result.updated and not result.removed_ids
    assert result.unchanged == len(links) == 12
