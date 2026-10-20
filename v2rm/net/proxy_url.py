"""Proxy URLs: `socks5://[user:pass@]host:port` and `http://[user:pass@]host:port`.

Used wherever a proxy that is already running -- another VPN client, a Tor client, the previous
hop of a chain -- has to be named: an Aether profile's upstream, an external hop of a chain.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote, unquote, urlsplit

from v2rm.errors import ProfileValidationError

_SOCKS_SCHEMES = {"socks5", "socks5h", "socks"}


@dataclass(frozen=True)
class ProxyEndpoint:
    scheme: str  # "socks5" or "http"
    host: str
    port: int
    user: str = ""
    password: str = ""

    @property
    def is_socks(self) -> bool:
        return self.scheme == "socks5"

    @property
    def has_credentials(self) -> bool:
        return bool(self.user or self.password)

    def url(self, *, hide_password: bool = False) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        userinfo = ""
        if self.has_credentials:
            password = "***" if hide_password and self.password else quote(self.password, safe="")
            userinfo = quote(self.user, safe="") + (f":{password}" if self.password else "") + "@"
        return f"{self.scheme}://{userinfo}{host}:{self.port}"


def parse_proxy_url(text: str) -> ProxyEndpoint:
    """A proxy URL, validated the way Aether validates its `--upstream`. A bare `host:port`
    means SOCKS5. Raises ProfileValidationError with a readable reason."""
    raw = (text or "").strip()
    if not raw:
        raise ProfileValidationError("An empty proxy address was given")

    scheme, sep, rest = raw.partition("://")
    if not sep:
        scheme, rest = "socks5", raw
    scheme = scheme.lower()

    if scheme == "https":
        raise ProfileValidationError(
            "An https:// proxy can't be used: v2rm and Aether talk to their upstream over plain HTTP. "
            "Write http://host:port (the traffic through it stays encrypted by the tunnel)."
        )
    if scheme in _SOCKS_SCHEMES:
        scheme = "socks5"
    elif scheme != "http":
        raise ProfileValidationError(
            f"'{scheme}://' is not a proxy kind that can be used here; use socks5://host:port or http://host:port"
        )

    try:
        parts = urlsplit(f"{scheme}://{rest.rstrip('/')}")
        host = parts.hostname
        port = parts.port
        user = unquote(parts.username) if parts.username is not None else ""
        password = unquote(parts.password) if parts.password is not None else ""
    except ValueError as exc:
        raise ProfileValidationError(f"'{redact(raw)}' is not a valid proxy address ({exc})") from exc

    if not host:
        raise ProfileValidationError(f"'{redact(raw)}' has no host; write it as {scheme}://host:port")
    if port is None:
        raise ProfileValidationError(f"'{redact(raw)}' has no port; write it as {scheme}://host:port")
    if not 1 <= port <= 65535:
        raise ProfileValidationError(f"'{redact(raw)}' has an invalid port: {port}")
    if (user or password) and "\n" in user + password:
        raise ProfileValidationError("The proxy credentials contain a line break")
    return ProxyEndpoint(scheme=scheme, host=host, port=port, user=user, password=password)


def redact(url: str) -> str:
    """The URL with any password replaced by ***, for messages and logs. Works on text that
    failed to parse too (the password may hold an '@', so the userinfo ends at the last one)."""
    text = url or ""
    scheme, sep, rest = text.partition("://")
    if not sep:
        scheme, rest = "", text
    authority, slash, tail = rest.partition("/")
    userinfo, at, hostinfo = authority.rpartition("@")
    if not at or ":" not in userinfo:
        return text
    user = userinfo.partition(":")[0]
    return f"{scheme}{sep}{user}:***@{hostinfo}{slash}{tail}"
