from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote

from v2rm.errors import V2rmError

# SOCKS5 (RFC 1929) length-prefixes the username and password with one byte.
MAX_CREDENTIAL_BYTES = 255


@dataclass(frozen=True)
class ProxyAuth:
    """Optional username/password for v2rm's local SOCKS/HTTP inbounds."""

    user: str
    password: str

    def userinfo(self) -> str:
        """`user:pass` percent-encoded for embedding in a proxy URL."""
        return f"{quote(self.user, safe='')}:{quote(self.password, safe='')}"

    @classmethod
    def parse(cls, value: str) -> ProxyAuth:
        """`USER:PASS` (split at the first colon, so the password may contain
        colons). Raises V2rmError for anything the proxy protocols or the
        shell-safe output formats couldn't carry."""
        user, colon, password = value.partition(":")
        if not colon or not user or not password:
            raise V2rmError("--auth must look like USER:PASS (a user, a colon, then a password; both non-empty)")
        for label, part in (("user name", user), ("password", password)):
            if len(part.encode("utf-8")) > MAX_CREDENTIAL_BYTES:
                raise V2rmError(f"The {label} is too long: SOCKS5 allows at most {MAX_CREDENTIAL_BYTES} bytes")
            if any(ord(ch) < 32 or ord(ch) == 127 for ch in part):
                raise V2rmError(f"The {label} contains control characters")
        return cls(user, password)
