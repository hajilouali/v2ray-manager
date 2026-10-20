from __future__ import annotations

from enum import Enum


class Protocol(str, Enum):
    VMESS = "vmess"
    VLESS = "vless"
    TROJAN = "trojan"
    SHADOWSOCKS = "shadowsocks"
    HYSTERIA2 = "hysteria2"
    TUIC = "tuic"
    MASQUE = "masque"
    # A complete, hand-written Xray config (no single server): e.g. "serverless"
    # DPI-evasion configs. Stored verbatim in Profile.raw_config.
    RAW_XRAY = "raw-xray"
    # Cloudflare WARP through Aether (MASQUE, WireGuard, gool, ...): no server of its own,
    # the settings are in Profile.aether.
    AETHER = "aether"
    # Other profiles strung together, each leaving through the one before: Profile.chain.
    CHAIN = "chain"


class SecurityKind(str, Enum):
    NONE = "none"
    TLS = "tls"
    REALITY = "reality"


class TransportKind(str, Enum):
    TCP = "tcp"
    WS = "ws"
    GRPC = "grpc"
    HTTP = "http"
    KCP = "kcp"
    QUIC = "quic"
    HTTPUPGRADE = "httpupgrade"
    XHTTP = "xhttp"


class ProfileSource(str, Enum):
    MANUAL = "manual"
    SUBSCRIPTION = "subscription"


class EngineKind(str, Enum):
    XRAY = "xray"
    SINGBOX = "singbox"
    # Cloudflare WARP over MASQUE / WireGuard / gool, run as its own program. Never the
    # default engine (`core use` offers xray and singbox only): it serves Aether profiles.
    AETHER = "aether"


class SubscriptionFormat(str, Enum):
    BASE64_LIST = "base64_list"
    PLAIN_LIST = "plain_list"
    CLASH_YAML = "clash_yaml"
    XRAY_JSON = "xray_json"


class RoutePreset(str, Enum):
    GLOBAL = "global"
    BYPASS_IR = "bypass-ir"
    BYPASS_CN = "bypass-cn"
    CUSTOM = "custom"
