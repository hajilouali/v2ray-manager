from __future__ import annotations

from v2rm.models.enums import Protocol
from v2rm.models.profile import Profile
from v2rm.subscription.sync import diff_subscription_members


def make(name: str, server: str, port: int = 443, uuid: str = "u1") -> Profile:
    return Profile(name=name, protocol=Protocol.VLESS, server=server, port=port, uuid=uuid)


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
    result = diff_subscription_members(
        [keep, gone], [make("Keep", "keep.example.com"), make("New", "new.example.com")]
    )

    assert len(result.added) == 1
    assert result.added[0].name == "New"
    assert len(result.updated) == 1
    assert result.updated[0].id == keep.id
    assert result.removed_ids == [gone.id]


def test_diff_different_uuid_is_treated_as_a_different_profile():
    old = make("Same server, different key", "a.example.com", uuid="u1")
    new = make("Same server, different key", "a.example.com", uuid="u2")
    result = diff_subscription_members([old], [new])
    assert len(result.added) == 1
    assert result.removed_ids == [old.id]
    assert not result.updated
