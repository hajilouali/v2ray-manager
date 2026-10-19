from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from v2rm.models.profile import Profile


@dataclass
class SyncResult:
    added: list[Profile]
    # Matched profiles whose content actually changed (name, transport, a raw
    # config's body, ...) -- carrying the existing profile's id.
    updated: list[Profile]
    removed_ids: list[str]
    # Ids of every matched existing profile, changed or not.
    kept_ids: list[str] = field(default_factory=list)

    @property
    def unchanged(self) -> int:
        return len(self.kept_ids) - len(self.updated)


def diff_subscription_members(existing: list[Profile], fetched: list[Profile]) -> SyncResult:
    """Match freshly-fetched profiles against a subscription's existing
    members by identity_key() rather than name, so a provider renaming a node
    doesn't spawn a duplicate and doesn't lose the profile's stable id --
    which matters when that id is the currently active/connected profile.

    Keys can repeat: real lists contain the same node several times under
    different labels (identical parameters, different names). Those are
    matched one-to-one, preferring the existing profile with the same name
    and otherwise taking them in order, so n copies fetched stay n copies
    (nothing collapses, nothing is wrongly removed or re-added)."""
    pools: dict[tuple[str, ...], list[Profile]] = defaultdict(list)
    for old in existing:
        pools[old.identity_key()].append(old)

    added: list[Profile] = []
    updated: list[Profile] = []
    kept_ids: list[str] = []

    for new in fetched:
        old = _take(pools.get(new.identity_key()), new.name)
        if old is None:
            added.append(new)
            continue
        kept_ids.append(old.id)
        merged = Profile.from_dict(new.to_dict())
        merged.id = old.id
        merged.created_at = old.created_at
        merged.source = old.source
        merged.subscription_id = old.subscription_id
        if merged.to_dict() != old.to_dict():
            updated.append(merged)

    kept = set(kept_ids)
    removed_ids = [p.id for p in existing if p.id not in kept]
    return SyncResult(added=added, updated=updated, removed_ids=removed_ids, kept_ids=kept_ids)


def _take(pool: list[Profile] | None, name: str) -> Profile | None:
    if not pool:
        return None
    for i, candidate in enumerate(pool):
        if candidate.name == name:
            return pool.pop(i)
    return pool.pop(0)
