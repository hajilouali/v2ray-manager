from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote

from v2rm.errors import V2rmError

# SOCKS5 (RFC 1929) length-prefixes the username and password with one byte.
MAX_CREDENTIAL_BYTES = 255


def _check_part(label: str, part: str) -> None:
    if len(part.encode("utf-8")) > MAX_CREDENTIAL_BYTES:
        raise V2rmError(f"The {label} is too long: SOCKS5 allows at most {MAX_CREDENTIAL_BYTES} bytes")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in part):
        raise V2rmError(f"The {label} contains control characters")


@dataclass(frozen=True)
class ProxyAuth:
    """Optional username/password for v2rm's local SOCKS/HTTP inbounds."""

    user: str
    password: str

    def userinfo(self) -> str:
        """`user:pass` percent-encoded for embedding in a proxy URL."""
        return f"{quote(self.user, safe='')}:{quote(self.password, safe='')}"

    @staticmethod
    def check_user(user: str) -> None:
        """Raises V2rmError if the proxy protocols couldn't carry this user name."""
        if not user:
            raise V2rmError("The user name can't be empty")
        if ":" in user:
            # HTTP proxy logins are sent as `user:password`, so a client splits at the first colon.
            raise V2rmError("The user name can't contain a colon")
        _check_part("user name", user)

    @staticmethod
    def check_password(password: str) -> None:
        """Raises V2rmError if the proxy protocols couldn't carry this password."""
        if not password:
            raise V2rmError("The password can't be empty")
        _check_part("password", password)

    @classmethod
    def build(cls, user: str, password: str) -> ProxyAuth:
        """A login from its two parts, checked for everything the proxy protocols
        or the shell-safe output formats couldn't carry."""
        cls.check_user(user)
        cls.check_password(password)
        return cls(user, password)

    @classmethod
    def parse(cls, value: str) -> ProxyAuth:
        """`USER:PASS` (split at the first colon, so the password may contain
        colons)."""
        user, colon, password = value.partition(":")
        if not colon or not user or not password:
            raise V2rmError("--auth must look like USER:PASS (a user, a colon, then a password; both non-empty)")
        return cls.build(user, password)
