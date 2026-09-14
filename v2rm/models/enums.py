from __future__ import annotations

from enum import Enum


class Protocol(str, Enum):
    VMESS = "vmess"
    VLESS = "vless"
    TROJAN = "trojan"
    SHADOWSOCKS = "shadowsocks"
    HYSTERIA2 = "hysteria2"
    TUIC = "tuic"


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


class SubscriptionFormat(str, Enum):
    BASE64_LIST = "base64_list"
    PLAIN_LIST = "plain_list"
    CLASH_YAML = "clash_yaml"


class RoutePreset(str, Enum):
    GLOBAL = "global"
    BYPASS_IR = "bypass-ir"
    BYPASS_CN = "bypass-cn"
    CUSTOM = "custom"
