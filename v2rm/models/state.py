from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from v2rm.constants import DEFAULT_HTTP_PORT, DEFAULT_SOCKS_PORT
from v2rm.models.enums import EngineKind, RoutePreset


@dataclass
class AppState:
    active_profile_id: str | None = None
    active_engine: EngineKind | None = None
    socks_port: int = DEFAULT_SOCKS_PORT
    http_port: int = DEFAULT_HTTP_PORT
    route_preset: RoutePreset = RoutePreset.GLOBAL

    def to_dict(self) -> dict[str, Any]:
        return {
            "active_profile_id": self.active_profile_id,
            "active_engine": self.active_engine.value if self.active_engine else None,
            "socks_port": self.socks_port,
            "http_port": self.http_port,
            "route_preset": self.route_preset.value,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AppState:
        engine = data.get("active_engine")
        return cls(
            active_profile_id=data.get("active_profile_id"),
            active_engine=EngineKind(engine) if engine else None,
            socks_port=int(data.get("socks_port", DEFAULT_SOCKS_PORT)),
            http_port=int(data.get("http_port", DEFAULT_HTTP_PORT)),
            route_preset=RoutePreset(data.get("route_preset", RoutePreset.GLOBAL.value)),
        )
