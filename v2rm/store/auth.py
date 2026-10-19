from __future__ import annotations

import contextlib
import os
import stat
from pathlib import Path

from v2rm.errors import V2rmError
from v2rm.models.auth import ProxyAuth
from v2rm.store import paths
from v2rm.store.json_store import atomic_write_json, load_json
from v2rm.store.lock import store_lock


class AuthStore:
    """The local proxy's credentials, kept apart from state.json in their own
    file that is always mode 0600 (the password is stored in the clear: it has
    to be written into the generated engine config anyway)."""

    def __init__(self, path: Path | None = None, lock_path: Path | None = None) -> None:
        self._path = path or paths.auth_file()
        self._lock_path = lock_path or paths.lock_file()

    def load(self) -> ProxyAuth | None:
        """The saved login, or None if there isn't one. A file that exists but
        can't be read fails loudly instead of meaning "no login": silently
        starting an open proxy when the user asked for a protected one is the
        wrong way to fail."""
        try:
            data = load_json(self._path, None)
        except (OSError, ValueError) as exc:
            raise self._corrupted() from exc
        if data is None:
            return None
        user, password = (data.get("user"), data.get("password")) if isinstance(data, dict) else (None, None)
        if not isinstance(user, str) or not isinstance(password, str) or not user or not password:
            raise self._corrupted()
        return ProxyAuth(user=user, password=password)

    def _corrupted(self) -> V2rmError:
        return V2rmError(
            f"The proxy login file {self._path} is unreadable, so v2rm can't tell whether the proxy should "
            "require a login. Set it again with `v2rm port set --auth USER:PASS`, or drop it with "
            "`v2rm port set --no-auth`."
        )

    def save(self, auth: ProxyAuth) -> None:
        with store_lock(self._lock_path):
            # mkstemp (inside atomic_write_json) already creates the file 0600;
            # chmod again so the guarantee doesn't rest on that detail.
            atomic_write_json(self._path, {"user": auth.user, "password": auth.password})
            with contextlib.suppress(OSError):
                os.chmod(self._path, stat.S_IRUSR | stat.S_IWUSR)

    def clear(self) -> bool:
        with store_lock(self._lock_path):
            try:
                self._path.unlink()
            except FileNotFoundError:
                return False
        return True
