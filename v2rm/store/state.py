from __future__ import annotations

from pathlib import Path

from v2rm.models.state import AppState
from v2rm.store import paths
from v2rm.store.json_store import atomic_write_json, load_json
from v2rm.store.lock import store_lock


class AppStateStore:
    def __init__(self, path: Path | None = None, lock_path: Path | None = None) -> None:
        self._path = path or paths.state_file()
        self._lock_path = lock_path or paths.lock_file()

    def load(self) -> AppState:
        data = load_json(self._path, None)
        if data is None:
            return AppState()
        return AppState.from_dict(data)

    def save(self, state: AppState) -> None:
        with store_lock(self._lock_path):
            atomic_write_json(self._path, state.to_dict())
