from __future__ import annotations

import copy
import hashlib
import json
import uuid as uuid_mod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from v2rm.models.aether import AetherSettings
from v2rm.models.chain import ChainHop
from v2rm.models.enums import ProfileSource, Protocol, SecurityKind, TransportKind

# Bumped whenever a profile gains stored fields that older parsers dropped, so
# the store can re-derive them from raw_link for profiles saved by an older
# version (see v2rm.parsers.migrate). A stored dict without "schema" is v1.
SCHEMA_VERSION = 2

# Shown instead of server:port for profiles that have no single server.
NO_SERVER = "—"


def new_id() -> str:
    return uuid_mod.uuid4().hex[:12]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def canonical_json(obj: Any) -> str:
    """Deterministic JSON text: sorted keys, no whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


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
    # Colon-separated cipher suite names, exactly as Xray's tlsSettings.cipherSuites
    # takes them (the `cs` share-link parameter).
    cipher_suites: str = ""
    # Encrypted ClientHello config, e.g. "cloudflare-ech.com+udp://1.1.1.1"
    # (the `ech` / `echConfigList` / `echcl` share-link parameters).
    ech_config_list: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "security": self.security.value,
            "sni": self.sni,
            "alpn": list(self.alpn),
            "fingerprint": self.fingerprint,
            "allow_insecure": self.allow_insecure,
            "reality": self.reality.to_dict() if self.reality else None,
            "cipher_suites": self.cipher_suites,
            "ech_config_list": self.ech_config_list,
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
            cipher_suites=data.get("cipher_suites", ""),
            ech_config_list=data.get("ech_config_list", ""),
        )


@dataclass
class TransportSettings:
    network: TransportKind = TransportKind.TCP
    path: str = ""
    host: str = ""
    service_name: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    # xhttp: `mode` (auto/packet-up/stream-up/stream-one) and the `extra` JSON object.
    mode: str = ""
    xhttp_extra: dict[str, Any] = field(default_factory=dict)
    # Xray `streamSettings.finalmask` (TLS-hello fragmentation, noise, ...) as a
    # JSON object (the `fm` share-link parameter), passed through verbatim.
    finalmask: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "network": self.network.value,
            "path": self.path,
            "host": self.host,
            "service_name": self.service_name,
            "headers": dict(self.headers),
            "mode": self.mode,
            "xhttp_extra": copy.deepcopy(self.xhttp_extra),
            "finalmask": copy.deepcopy(self.finalmask),
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
            mode=data.get("mode", ""),
            xhttp_extra=copy.deepcopy(data.get("xhttp_extra") or {}),
            finalmask=copy.deepcopy(data.get("finalmask") or {}),
        )


@dataclass
class Profile:
    name: str
    protocol: Protocol
    # Optional: a raw Xray profile has no single server/port.
    server: str = ""
    port: int = 0
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
    # VLESS post-quantum encryption string (mlkem768x25519plus...). Empty means "none".
    encryption: str = ""
    # VLESS/VMess packet encoding (xudp/packet/none) as given in the link.
    packet_encoding: str = ""

    transport: TransportSettings = field(default_factory=TransportSettings)
    tls: TlsSettings = field(default_factory=TlsSettings)

    # Long-tail per-protocol knobs that don't earn a first-class field: hysteria2
    # obfs/obfs_password/up_mbps/down_mbps, tuic udp_relay_mode/zero_rtt_handshake,
    # shadowsocks plugin/plugin_opts, masque user/warp/remote_dns, legacy `fragment`.
    # Generators read these via .get() with defaults.
    extra: dict[str, Any] = field(default_factory=dict)

    # The complete Xray config of a raw-xray profile (None for every other kind).
    raw_config: dict[str, Any] | None = None

    # The settings of an Aether profile, and the hops of a chain (None for every other kind).
    aether: AetherSettings | None = None
    chain: list[ChainHop] | None = None

    schema: int = SCHEMA_VERSION

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
            "encryption": self.encryption,
            "packet_encoding": self.packet_encoding,
            "transport": self.transport.to_dict(),
            "tls": self.tls.to_dict(),
            "extra": copy.deepcopy(self.extra),
            "raw_config": copy.deepcopy(self.raw_config),
            "aether": self.aether.to_dict() if self.aether else None,
            "chain": [hop.to_dict() for hop in self.chain] if self.chain is not None else None,
            "schema": self.schema,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Profile:
        raw_config = data.get("raw_config")
        aether = data.get("aether")
        chain = data.get("chain")
        return cls(
            id=data["id"],
            name=data["name"],
            protocol=Protocol(data["protocol"]),
            server=data.get("server", ""),
            port=int(data.get("port", 0) or 0),
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
            encryption=data.get("encryption", ""),
            packet_encoding=data.get("packet_encoding", ""),
            transport=TransportSettings.from_dict(data.get("transport")),
            tls=TlsSettings.from_dict(data.get("tls")),
            extra=copy.deepcopy(data.get("extra") or {}),
            raw_config=copy.deepcopy(raw_config) if raw_config is not None else None,
            aether=AetherSettings.from_dict(aether) if isinstance(aether, dict) else None,
            chain=[ChainHop.from_dict(h) for h in chain if isinstance(h, dict)] if isinstance(chain, list) else None,
            schema=int(data.get("schema", 1)),
        )

    @property
    def is_raw(self) -> bool:
        return self.protocol == Protocol.RAW_XRAY

    @property
    def is_aether(self) -> bool:
        return self.protocol == Protocol.AETHER

    @property
    def is_chain(self) -> bool:
        return self.protocol == Protocol.CHAIN

    @property
    def type_label(self) -> str:
        """Short label for the profile list's Type column."""
        return "raw" if self.is_raw else self.protocol.value

    @property
    def server_display(self) -> str:
        if self.is_aether:
            return (self.aether or AetherSettings()).summary()
        if self.is_chain:
            return " -> ".join(hop.label() for hop in self.chain or []) or NO_SERVER
        if self.is_raw or not self.server:
            return NO_SERVER
        return f"{self.server}:{self.port}"

    def variant_hash(self) -> str:
        """Short hash of the parameters that distinguish variants of the same
        node: providers publish one server several times, differing only in
        fingerprint / cipher suites / finalmask / ECH / VLESS encryption /
        xhttp extra+mode. Excludes the display name, so it's stable across
        refreshes."""
        variant = {
            "fp": self.tls.fingerprint,
            "cs": self.tls.cipher_suites,
            "fm": self.transport.finalmask,
            "ech": self.tls.ech_config_list,
            "encryption": self.encryption,
            "extra": self.transport.xhttp_extra,
            "mode": self.transport.mode,
        }
        return _sha256_hex(canonical_json(variant))[:12]

    def identity_key(self) -> tuple[str, ...]:
        """Stable identity used to match this profile across subscription
        refreshes, independent of its display name (which providers rename)."""
        if self.protocol == Protocol.RAW_XRAY:
            config = self.raw_config or {}
            remarks = str(config.get("remarks") or "").strip()
            if remarks:
                return (self.protocol.value, remarks)
            return (self.protocol.value, "sha256:" + _sha256_hex(canonical_json(config)))

        if self.protocol in (Protocol.AETHER, Protocol.CHAIN):
            # Made by hand, never by a subscription, so nothing is matched across refreshes:
            # the profile's own id is its identity.
            return (self.protocol.value, self.id)

        if self.protocol == Protocol.MASQUE:
            return (
                self.protocol.value,
                self.server,
                str(self.port),
                str(self.extra.get("user", "")),
                self.tls.sni,
                self.transport.path,
            )

        base = (self.protocol.value, self.server, str(self.port), self.uuid, self.password)
        if self.protocol in (Protocol.VLESS, Protocol.TROJAN, Protocol.VMESS):
            return base + (
                self.tls.sni,
                self.transport.host,
                self.transport.path,
                self.transport.network.value,
                self.variant_hash(),
            )
        return base
