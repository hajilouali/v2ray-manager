"""The connectivity test's failure messages, and the URLs it tries (found on a real server:
the fallback URL had started returning 404, and only the *last* error was ever shown)."""

from __future__ import annotations

import pytest
import requests

from v2rm.constants import TEST_URLS
from v2rm.net.speedtest import run_connectivity_test, short_error

from .test_net_speedtest import FakeStreamResponse


def test_the_fallback_url_is_one_that_exists():
    # CacheFly serves 1mb/10mb/100mb.test; "2mb.test" is a 404.
    assert TEST_URLS == [
        "https://speed.cloudflare.com/__down?bytes=2000000",
        "https://cachefly.cachefly.net/10mb.test",
    ]


def test_every_endpoints_reason_is_reported_not_just_the_last(monkeypatch):
    class DownEverywhere:
        def get(self, url, stream=True, timeout=None):
            if "cloudflare" in url:
                raise requests.ConnectionError(
                    "SOCKSHTTPSConnectionPool(host='speed.cloudflare.com', port=443): Read timed out. (read timeout=12.0)"
                )
            return FakeStreamResponse([b"x"], status_code=404)

    monkeypatch.setattr("v2rm.net.speedtest.build_proxy_session", lambda port, auth=None: DownEverywhere())
    result = run_connectivity_test(10808, timeout=12)
    assert result.ok is False
    assert result.error == "speed.cloudflare.com: timed out (no data within 12s); cachefly.cachefly.net: HTTP 404"


def test_a_working_fallback_still_wins(monkeypatch):
    class OnlySecondWorks:
        def get(self, url, stream=True, timeout=None):
            if "cloudflare" in url:
                raise requests.ConnectionError("boom")
            return FakeStreamResponse([b"data"])

    monkeypatch.setattr("v2rm.net.speedtest.build_proxy_session", lambda port, auth=None: OnlySecondWorks())
    result = run_connectivity_test(10808, timeout=5)
    assert result.ok is True and "cachefly" in result.url


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        (
            "SOCKSHTTPSConnectionPool(host='x.example', port=443): Read timed out. (read timeout=12.0)",
            "timed out (no data within 10s)",
        ),
        (
            "SOCKSHTTPSConnectionPool(host='x.example', port=443): Max retries exceeded with url: /f (Caused by "
            "SSLError(SSLEOFError(8, '[SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1007)')))",
            "SSLError(SSLEOFError(8, '[SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1007)'))",
        ),
        ("Connection to x.example timed out. (connect timeout=10)", "timed out (no data within 10s)"),
        ("HTTP 404", "HTTP 404"),
        ("   spaced \n out  ", "spaced out"),
    ],
)
def test_short_error_phrases(message, expected):
    assert short_error(requests.ConnectionError(message), 10) == expected


def test_very_long_errors_are_cut():
    assert len(short_error(RuntimeError("x" * 1000), 10)) == 140

