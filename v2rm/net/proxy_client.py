from __future__ import annotations

import requests

from v2rm.models.auth import ProxyAuth


def build_proxy_session(socks_port: int, auth: ProxyAuth | None = None) -> requests.Session:
    """A requests.Session pinned to the local SOCKS proxy on `socks_port`,
    resolving DNS through the tunnel (socks5h, not socks5) and ignoring any
    http_proxy/https_proxy already set in the environment -- e.g. by a
    shell that has `eval`'d `v2rm env` -- so the test measures exactly the
    port it was asked to. If the proxy requires a login, `auth` is sent
    with every connection."""
    session = requests.Session()
    userinfo = f"{auth.userinfo()}@" if auth is not None else ""
    proxy_url = f"socks5h://{userinfo}127.0.0.1:{socks_port}"
    session.proxies = {"http": proxy_url, "https": proxy_url}
    session.trust_env = False
    return session
