"""Asking the installed `aether` program whether it runs at all."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from v2rm.engines.aether.env import scrubbed_environment

# What the loader says when the program was built for a newer glibc than this system has.
GLIBC_MARKERS = ("GLIBC_", "version `GLIBC", "libc.so", "not found")


def aether_runs(binary: Path, timeout: float = 10.0) -> tuple[bool, str]:
    """(it runs, what `aether --version` said or why it could not). A glibc build on an older
    distribution fails right here, before it ever gets to a tunnel."""
    try:
        proc = subprocess.run(
            [str(binary), "--version"],
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=timeout,
            env=scrubbed_environment(dict(os.environ)),
        )
    except subprocess.TimeoutExpired:
        return False, "it did not answer `--version` in time"
    except OSError as exc:
        return False, str(exc)
    text = ((proc.stdout or "") + (proc.stderr or "")).strip().splitlines()
    first = text[0].strip() if text else ""
    if proc.returncode != 0:
        return False, first or f"exit code {proc.returncode}"
    return True, first or "ok"


def looks_like_glibc_mismatch(message: str) -> bool:
    return any(marker in message for marker in GLIBC_MARKERS)
