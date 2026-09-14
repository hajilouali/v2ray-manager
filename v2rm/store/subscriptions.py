from __future__ import annotations

from pathlib import Path

from v2rm.errors import AmbiguousReferenceError, SubscriptionNotFoundError
from v2rm.models.subscription import Subscription
from v2rm.store import paths
from v2rm.store.json_store import atomic_write_json, load_json
from v2rm.store.lock import store_lock


class SubscriptionStore:
    def __init__(self, path: Path | None = None, lock_path: Path | None = None) -> None:
        self._path = path or paths.subscriptions_file()
        self._lock_path = lock_path or paths.lock_file()

    def _load_raw(self) -> list[dict]:
        data = load_json(self._path, {"subscriptions": []})
        return data.get("subscriptions", [])

    def _save_raw(self, items: list[dict]) -> None:
        atomic_write_json(self._path, {"subscriptions": items})

    def list(self) -> list[Subscription]:
        return [Subscription.from_dict(item) for item in self._load_raw()]

    def get(self, sub_id: str) -> Subscription | None:
        for item in self._load_raw():
            if item["id"] == sub_id:
                return Subscription.from_dict(item)
        return None

    def resolve(self, ref: str) -> Subscription:
        subs = self.list()
        for s in subs:
            if s.id == ref:
                return s

        name_matches = [s for s in subs if s.name == ref]
        if len(name_matches) == 1:
            return name_matches[0]
        if len(name_matches) > 1:
            raise AmbiguousReferenceError(
                f"'{ref}' matches {len(name_matches)} subscriptions by name; use the id instead"
            )

        prefix_matches = [s for s in subs if s.id.startswith(ref)]
        if len(prefix_matches) == 1:
            return prefix_matches[0]
        if len(prefix_matches) > 1:
            raise AmbiguousReferenceError(
                f"'{ref}' matches {len(prefix_matches)} subscription ids; use a longer prefix"
            )

        raise SubscriptionNotFoundError(f"No subscription found matching '{ref}'")

    def add(self, subscription: Subscription) -> Subscription:
        with store_lock(self._lock_path):
            items = self._load_raw()
            items.append(subscription.to_dict())
            self._save_raw(items)
        return subscription

    def update(self, subscription: Subscription) -> None:
        with store_lock(self._lock_path):
            items = self._load_raw()
            for i, item in enumerate(items):
                if item["id"] == subscription.id:
                    items[i] = subscription.to_dict()
                    self._save_raw(items)
                    return
        raise SubscriptionNotFoundError(f"No subscription found with id '{subscription.id}'")

    def remove(self, sub_id: str) -> None:
        with store_lock(self._lock_path):
            items = self._load_raw()
            new_items = [i for i in items if i["id"] != sub_id]
            if len(new_items) == len(items):
                raise SubscriptionNotFoundError(f"No subscription found with id '{sub_id}'")
            self._save_raw(new_items)
