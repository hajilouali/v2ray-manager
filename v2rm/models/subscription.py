from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from v2rm.models.enums import SubscriptionFormat
from v2rm.models.profile import new_id


@dataclass
class Subscription:
    name: str
    url: str
    id: str = field(default_factory=new_id)
    format_hint: SubscriptionFormat | None = None
    user_agent: str | None = None
    last_updated: str | None = None
    last_status: str = "never"
    profile_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "url": self.url,
            "format_hint": self.format_hint.value if self.format_hint else None,
            "user_agent": self.user_agent,
            "last_updated": self.last_updated,
            "last_status": self.last_status,
            "profile_ids": list(self.profile_ids),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Subscription:
        fmt = data.get("format_hint")
        return cls(
            id=data["id"],
            name=data["name"],
            url=data["url"],
            format_hint=SubscriptionFormat(fmt) if fmt else None,
            user_agent=data.get("user_agent"),
            last_updated=data.get("last_updated"),
            last_status=data.get("last_status", "never"),
            profile_ids=list(data.get("profile_ids", [])),
        )
