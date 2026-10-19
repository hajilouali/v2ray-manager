from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote


@dataclass(frozen=True)
class ProxyAuth:
    """Optional username/password for v2rm's local SOCKS/HTTP inbounds."""

    user: str
    password: str

    def userinfo(self) -> str:
        """`user:pass` percent-encoded for embedding in a proxy URL."""
        return f"{quote(self.user, safe='')}:{quote(self.password, safe='')}"
