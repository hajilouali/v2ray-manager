from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from v2rm.errors import AmbiguousReferenceError, ProfileNotFoundError
from v2rm.models.profile import Profile
from v2rm.store import paths
from v2rm.store.json_store import atomic_write_json, load_json
from v2rm.store.lock import store_lock


class ProfileStore:
    def __init__(self, path: Path | None = None, lock_path: Path | None = None) -> None:
        self._path = path or paths.profiles_file()
        self._lock_path = lock_path or paths.lock_file()

    def _load_raw(self) -> list[dict]:
        data = load_json(self._path, {"profiles": []})
        return data.get("profiles", [])

    def _save_raw(self, items: list[dict]) -> None:
        atomic_write_json(self._path, {"profiles": items})

    def list(self) -> list[Profile]:
        return [Profile.from_dict(item) for item in self._load_raw()]

    def list_by_subscription(self, subscription_id: str) -> list[Profile]:
        return [p for p in self.list() if p.subscription_id == subscription_id]

    def get(self, profile_id: str) -> Profile | None:
        for item in self._load_raw():
            if item["id"] == profile_id:
                return Profile.from_dict(item)
        return None

    def resolve(self, ref: str) -> Profile:
        """Resolve a user-supplied reference to exactly one profile: full id,
        then exact name, then unambiguous id prefix. Raises ProfileNotFoundError
        or AmbiguousReferenceError otherwise."""
        profiles = self.list()
        for p in profiles:
            if p.id == ref:
                return p

        name_matches = [p for p in profiles if p.name == ref]
        if len(name_matches) == 1:
            return name_matches[0]
        if len(name_matches) > 1:
            raise AmbiguousReferenceError(
                f"'{ref}' matches {len(name_matches)} profiles by name; use the id instead"
            )

        prefix_matches = [p for p in profiles if p.id.startswith(ref)]
        if len(prefix_matches) == 1:
            return prefix_matches[0]
        if len(prefix_matches) > 1:
            raise AmbiguousReferenceError(
                f"'{ref}' matches {len(prefix_matches)} profile ids; use a longer prefix"
            )

        raise ProfileNotFoundError(f"No profile found matching '{ref}'")

    def add(self, profile: Profile) -> Profile:
        with store_lock(self._lock_path):
            items = self._load_raw()
            items.append(profile.to_dict())
            self._save_raw(items)
        return profile

    def add_many(self, profiles: Iterable[Profile]) -> list[Profile]:
        profiles = list(profiles)
        with store_lock(self._lock_path):
            items = self._load_raw()
            items.extend(p.to_dict() for p in profiles)
            self._save_raw(items)
        return profiles

    def update(self, profile: Profile) -> None:
        with store_lock(self._lock_path):
            items = self._load_raw()
            for i, item in enumerate(items):
                if item["id"] == profile.id:
                    items[i] = profile.to_dict()
                    self._save_raw(items)
                    return
        raise ProfileNotFoundError(f"No profile found with id '{profile.id}'")

    def remove(self, profile_id: str) -> None:
        with store_lock(self._lock_path):
            items = self._load_raw()
            new_items = [i for i in items if i["id"] != profile_id]
            if len(new_items) == len(items):
                raise ProfileNotFoundError(f"No profile found with id '{profile_id}'")
            self._save_raw(new_items)

    def remove_many(self, profile_ids: Iterable[str]) -> int:
        ids = set(profile_ids)
        with store_lock(self._lock_path):
            items = self._load_raw()
            new_items = [i for i in items if i["id"] not in ids]
            removed = len(items) - len(new_items)
            if removed:
                self._save_raw(new_items)
        return removed
