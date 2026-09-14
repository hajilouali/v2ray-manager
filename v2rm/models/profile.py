from __future__ import annotations

import uuid as uuid_mod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from v2rm.models.enums import Protocol, ProfileSource, SecurityKind, TransportKind


def new_id() -> str:
    return uuid_mod.uuid4().hex[:12]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class RealitySettings:
    public_key: str = ""
    short_id: str = ""
    spider_x: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"public_key": self.public_key, "short_id": self.short_id, "spider_x": self.spider_x}

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> RealitySettings | None:
        if not data:
            return None
        return cls(
            public_key=data.get("public_key", ""),
            short_id=data.get("short_id", ""),
            spider_x=data.get("spider_x", ""),
        )


@dataclass
class TlsSettings:
    security: SecurityKind = SecurityKind.NONE
    sni: str = ""
    alpn: list[str] = field(default_factory=list)
    fingerprint: str = ""
    allow_insecure: bool = False
    reality: RealitySettings | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "security": self.security.value,
            "sni": self.sni,
            "alpn": list(self.alpn),
            "fingerprint": self.fingerprint,
            "allow_insecure": self.allow_insecure,
            "reality": self.reality.to_dict() if self.reality else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> TlsSettings:
        data = data or {}
        return cls(
            security=SecurityKind(data.get("security", SecurityKind.NONE.value)),
            sni=data.get("sni", ""),
            alpn=list(data.get("alpn", [])),
            fingerprint=data.get("fingerprint", ""),
            allow_insecure=bool(data.get("allow_insecure", False)),
            reality=RealitySettings.from_dict(data.get("reality")),
        )


@dataclass
class TransportSettings:
    network: TransportKind = TransportKind.TCP
    path: str = ""
    host: str = ""
    service_name: str = ""
    headers: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "network": self.network.value,
            "path": self.path,
            "host": self.host,
            "service_name": self.service_name,
            "headers": dict(self.headers),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> TransportSettings:
        data = data or {}
        return cls(
            network=TransportKind(data.get("network", TransportKind.TCP.value)),
            path=data.get("path", ""),
            host=data.get("host", ""),
            service_name=data.get("service_name", ""),
            headers=dict(data.get("headers", {})),
        )


@dataclass
class Profile:
    name: str
    protocol: Protocol
    server: str
    port: int
    id: str = field(default_factory=new_id)
    created_at: str = field(default_factory=now_iso)
    source: ProfileSource = ProfileSource.MANUAL
    subscription_id: str | None = None
    raw_link: str | None = None

    uuid: str = ""
    alter_id: int = 0
    password: str = ""
    method: str = ""
    flow: str = ""
    congestion_control: str = ""

    transport: TransportSettings = field(default_factory=TransportSettings)
    tls: TlsSettings = field(default_factory=TlsSettings)

    # Long-tail per-protocol knobs that don't earn a first-class field: hysteria2
    # obfs/obfs_password/up_mbps/down_mbps, tuic udp_relay_mode/zero_rtt_handshake,
    # shadowsocks plugin/plugin_opts. Generators read these via .get() with defaults.
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "protocol": self.protocol.value,
            "server": self.server,
            "port": self.port,
            "created_at": self.created_at,
            "source": self.source.value,
            "subscription_id": self.subscription_id,
            "raw_link": self.raw_link,
            "uuid": self.uuid,
            "alter_id": self.alter_id,
            "password": self.password,
            "method": self.method,
            "flow": self.flow,
            "congestion_control": self.congestion_control,
            "transport": self.transport.to_dict(),
            "tls": self.tls.to_dict(),
            "extra": dict(self.extra),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Profile:
        return cls(
            id=data["id"],
            name=data["name"],
            protocol=Protocol(data["protocol"]),
            server=data["server"],
            port=int(data["port"]),
            created_at=data.get("created_at", now_iso()),
            source=ProfileSource(data.get("source", ProfileSource.MANUAL.value)),
            subscription_id=data.get("subscription_id"),
            raw_link=data.get("raw_link"),
            uuid=data.get("uuid", ""),
            alter_id=int(data.get("alter_id", 0)),
            password=data.get("password", ""),
            method=data.get("method", ""),
            flow=data.get("flow", ""),
            congestion_control=data.get("congestion_control", ""),
            transport=TransportSettings.from_dict(data.get("transport")),
            tls=TlsSettings.from_dict(data.get("tls")),
            extra=dict(data.get("extra", {})),
        )

    @property
    def server_display(self) -> str:
        return f"{self.server}:{self.port}"

    def identity_key(self) -> tuple[str, ...]:
        """Stable identity used to match this profile across subscription refreshes,
        independent of its display name (which providers sometimes rename)."""
        return (
            self.protocol.value,
            self.server,
            str(self.port),
            self.uuid,
            self.password,
        )
