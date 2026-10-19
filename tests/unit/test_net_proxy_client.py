from __future__ import annotations

from v2rm.models.auth import ProxyAuth
from v2rm.net.proxy_client import build_proxy_session


def test_build_proxy_session_uses_socks5h_and_ignores_env():
    session = build_proxy_session(10808)
    assert session.proxies["http"] == "socks5h://127.0.0.1:10808"
    assert session.proxies["https"] == "socks5h://127.0.0.1:10808"
    assert session.trust_env is False


def test_the_proxy_login_is_embedded_percent_encoded():
    session = build_proxy_session(10808, ProxyAuth("us er", "p@ss:w/rd"))
    expected = "socks5h://us%20er:p%40ss%3Aw%2Frd@127.0.0.1:10808"
    assert session.proxies == {"http": expected, "https": expected}
    assert session.trust_env is False
