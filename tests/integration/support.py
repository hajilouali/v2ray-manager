"""Shared helpers of the integration tests that run real Xray programs on loopback."""

from __future__ import annotations

import requests

from v2rm.models.auth import ProxyAuth


def socks_get(port: int, url: str, auth: ProxyAuth | None = None, timeout: float = 10) -> requests.Response:
    userinfo = f"{auth.userinfo()}@" if auth else ""
    proxy = f"socks5h://{userinfo}127.0.0.1:{port}"
    return requests.get(url, proxies={"http": proxy, "https": proxy}, timeout=timeout)


def http_proxy_get(port: int, url: str, auth: ProxyAuth | None = None, timeout: float = 10) -> requests.Response:
    userinfo = f"{auth.userinfo()}@" if auth else ""
    proxy = f"http://{userinfo}127.0.0.1:{port}"
    return requests.get(url, proxies={"http": proxy, "https": proxy}, timeout=timeout)


def trojan_server(port: int) -> dict:
    """An Xray "server" on loopback. Its freedom outbound refuses private addresses by default
    (Xray's own safety net) and the targets here are on loopback, so allow them explicitly."""
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"listen": "127.0.0.1", "port": port, "protocol": "trojan", "settings": {"clients": [{"password": "pw"}]}}
        ],
        "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}],
    }


def plain_socks_hop(port: int, access_log) -> dict:
    """A SOCKS proxy that dials directly, logging what it is asked to reach."""
    return {
        "log": {"loglevel": "info", "access": str(access_log)},
        "inbounds": [
            {"tag": "socks-in", "listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": {"auth": "noauth", "udp": True}}
        ],
        "outbounds": [{"protocol": "freedom", "settings": {}}],
    }
