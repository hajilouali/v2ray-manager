from __future__ import annotations

from v2rm.net.proxy_client import build_proxy_session


def test_build_proxy_session_uses_socks5h_and_ignores_env():
    session = build_proxy_session(10808)
    assert session.proxies["http"] == "socks5h://127.0.0.1:10808"
    assert session.proxies["https"] == "socks5h://127.0.0.1:10808"
    assert session.trust_env is False
