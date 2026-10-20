"""A chain: connections strung together, the traffic of each leaving through the one before.

The hops are listed the way the traffic travels -- the first is the one closest to you, the last
is the one the internet sees. A hop is either one of v2rm's saved profiles or the address of a
proxy already running somewhere (another VPN client, a Tor client, ...).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

HOP_PROFILE = "profile"
HOP_PROXY = "proxy"


@dataclass
class ChainHop:
    kind: str = HOP_PROFILE
    # A profile id (kind "profile") or a proxy URL such as socks5://127.0.0.1:1080 (kind "proxy").
    ref: str = ""
    # The profile's name when the chain was made: lets a chain survive its profile being
    # re-created under a new id (a subscription refresh does that), and reads well in errors.
    name: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "ref": self.ref, "name": self.name}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ChainHop:
        kind = str(data.get("kind") or HOP_PROFILE)
        return cls(
            kind=kind if kind in (HOP_PROFILE, HOP_PROXY) else HOP_PROFILE,
            ref=str(data.get("ref") or ""),
            name=str(data.get("name") or ""),
        )

    @property
    def is_proxy(self) -> bool:
        return self.kind == HOP_PROXY

    def label(self) -> str:
        """What to call this hop in messages. A proxy URL's password is never shown."""
        if self.is_proxy:
            from v2rm.net.proxy_url import redact

            return redact(self.ref)
        return self.name or self.ref
