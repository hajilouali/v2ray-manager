from __future__ import annotations

import contextlib
import os
import time
from collections.abc import Iterator
from pathlib import Path

from v2rm.errors import StoreLockTimeoutError

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX dev environments only
    fcntl = None  # type: ignore[assignment]


@contextlib.contextmanager
def store_lock(lock_path: Path, timeout: float = 5.0) -> Iterator[None]:
    """Advisory exclusive lock guarding store-mutating operations, so two
    concurrent `v2rm` invocations (e.g. an interactive `connect` and a
    scheduled `sub update --all`) can't interleave writes. No-ops on non-POSIX
    dev environments (fcntl is always present on the Linux deployment target)."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    if fcntl is None:
        yield
        return

    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR)
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise StoreLockTimeoutError(
                        f"Could not acquire store lock at {lock_path} within {timeout}s "
                        "(another v2rm command may be running)"
                    ) from None
                time.sleep(0.05)
        yield
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
