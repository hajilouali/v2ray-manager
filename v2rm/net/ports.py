"""Picking unused loopback ports for the engines v2rm starts behind the scenes."""

from __future__ import annotations

import socket
import threading

_handed_out: set[int] = set()
_handed_out_lock = threading.Lock()


def free_port(avoid: int | None = None) -> int:
    """An unused loopback port. The probe socket is closed before the engine binds, so with
    several workers (`test --all`) or several stages starting at once two of them could be
    given the same port; remembering what has been handed out in this process closes that gap."""
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        with _handed_out_lock:
            if port != avoid and port not in _handed_out:
                _handed_out.add(port)
                return port
