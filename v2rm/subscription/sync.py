from __future__ import annotations

from dataclasses import dataclass

from v2rm.models.profile import Profile


@dataclass
class SyncResult:
    added: list[Profile]
    updated: list[Profile]
    removed_ids: list[str]


def diff_subscription_members(existing: list[Profile], fetched: list[Profile]) -> SyncResult:
    """Match freshly-fetched profiles against a subscription's existing
    members by identity_key() (protocol+server+port+uuid/password) rather
    than name, so a provider renaming a node doesn't spawn a duplicate and
    doesn't lose the profile's stable id -- which matters when that id is
    referenced as the currently active/connected profile."""
    existing_by_key = {p.identity_key(): p for p in existing}
    fetched_keys_seen: set[tuple[str, ...]] = set()

    added: list[Profile] = []
    updated: list[Profile] = []

    for new_profile in fetched:
        key = new_profile.identity_key()
        fetched_keys_seen.add(key)
        old = existing_by_key.get(key)
        if old is None:
            added.append(new_profile)
        else:
            merged = Profile.from_dict(new_profile.to_dict())
            merged.id = old.id
            merged.created_at = old.created_at
            merged.source = old.source
            merged.subscription_id = old.subscription_id
            updated.append(merged)

    removed_ids = [p.id for p in existing if p.identity_key() not in fetched_keys_seen]

    return SyncResult(added=added, updated=updated, removed_ids=removed_ids)
