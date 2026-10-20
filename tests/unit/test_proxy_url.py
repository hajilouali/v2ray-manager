from __future__ import annotations

import pytest

from v2rm.errors import ProfileValidationError
from v2rm.net.proxy_url import ProxyEndpoint, parse_proxy_url, redact


def test_a_socks5_url_with_credentials():
    endpoint = parse_proxy_url("socks5://alice:s3cret@127.0.0.1:1080")
    assert endpoint == ProxyEndpoint("socks5", "127.0.0.1", 1080, "alice", "s3cret")
    assert endpoint.is_socks and endpoint.has_credentials


@pytest.mark.parametrize("scheme", ["socks5", "socks5h", "socks", "SOCKS5"])
def test_every_socks_spelling_means_socks5(scheme):
    assert parse_proxy_url(f"{scheme}://127.0.0.1:1080").scheme == "socks5"


def test_a_bare_host_and_port_means_socks5_as_it_does_in_aether():
    assert parse_proxy_url("127.0.0.1:9050").scheme == "socks5"


def test_an_http_proxy():
    endpoint = parse_proxy_url("http://proxy.example:8080")
    assert (endpoint.scheme, endpoint.host, endpoint.port) == ("http", "proxy.example", 8080)
    assert not endpoint.is_socks


def test_credentials_are_percent_decoded_and_a_password_may_hold_an_at_sign():
    endpoint = parse_proxy_url("socks5://us%40er:p%3Ass@h.example:1080")
    assert (endpoint.user, endpoint.password) == ("us@er", "p:ss")
    assert parse_proxy_url("socks5://u:p@ss@h.example:1080").password == "p@ss"


def test_an_ipv6_host_keeps_its_brackets_in_the_url():
    endpoint = parse_proxy_url("socks5://[::1]:1080")
    assert endpoint.host == "::1"
    assert endpoint.url() == "socks5://[::1]:1080"


def test_https_is_refused_with_the_reason():
    with pytest.raises(ProfileValidationError, match="plain HTTP"):
        parse_proxy_url("https://proxy.example:8443")


@pytest.mark.parametrize(
    "bad, fragment",
    [
        ("", "empty"),
        ("ftp://h:21", "not a proxy kind"),
        ("socks5://127.0.0.1", "no port"),
        ("socks5://:1080", "no host"),
        ("socks5://h:99999", "out of range"),
        ("socks5://h:0", "invalid port"),
    ],
)
def test_bad_addresses_say_what_is_wrong(bad, fragment):
    with pytest.raises(ProfileValidationError, match=fragment):
        parse_proxy_url(bad)


def test_url_round_trips_and_can_hide_the_password():
    endpoint = parse_proxy_url("socks5://alice:p%40ss@127.0.0.1:1080")
    assert parse_proxy_url(endpoint.url()) == endpoint
    assert endpoint.url(hide_password=True) == "socks5://alice:***@127.0.0.1:1080"


@pytest.mark.parametrize(
    "text, expected",
    [
        ("socks5://alice:s3cret@127.0.0.1:1080", "socks5://alice:***@127.0.0.1:1080"),
        ("socks5://u:p@ss@h:1080", "socks5://u:***@h:1080"),
        ("alice:s3cret@127.0.0.1:1080", "alice:***@127.0.0.1:1080"),
        ("socks5://127.0.0.1:1080", "socks5://127.0.0.1:1080"),
        ("socks5://onlyuser@127.0.0.1:1080", "socks5://onlyuser@127.0.0.1:1080"),
        ("", ""),
    ],
)
def test_redact_hides_a_password_wherever_the_text_came_from(text, expected):
    assert redact(text) == expected
