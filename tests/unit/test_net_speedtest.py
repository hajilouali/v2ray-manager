from __future__ import annotations

import pytest
import requests

from v2rm.errors import V2rmError
from v2rm.net.speedtest import _download_and_measure, run_connectivity_test


class FakeStreamResponse:
    def __init__(self, chunks: list[bytes], status_code: int = 200):
        self._chunks = chunks
        self.status_code = status_code

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")

    def iter_content(self, chunk_size=65536):
        yield from self._chunks


class FakeSession:
    def __init__(self, chunks: list[bytes]):
        self._chunks = chunks

    def get(self, url, stream=True, timeout=None):
        return FakeStreamResponse(self._chunks)


def test_download_and_measure_computes_latency_and_throughput():
    session = FakeSession([b"x" * 1000, b"y" * 1000])
    result = _download_and_measure(session, "http://test", timeout=5)

    assert result.ok is True
    assert result.bytes_downloaded == 2000
    assert result.latency_ms is not None and result.latency_ms >= 0
    assert result.throughput_mbps is not None and result.throughput_mbps > 0
    assert result.url == "http://test"


def test_download_and_measure_no_data_raises():
    session = FakeSession([])
    with pytest.raises(V2rmError):
        _download_and_measure(session, "http://test", timeout=5)


def test_run_connectivity_test_falls_back_to_second_url(monkeypatch):
    calls = []

    class FlakySession:
        def get(self, url, stream=True, timeout=None):
            calls.append(url)
            if url == "http://bad":
                raise requests.ConnectionError("nope")
            return FakeStreamResponse([b"ok-data"])

    monkeypatch.setattr("v2rm.net.speedtest.build_proxy_session", lambda port, auth=None: FlakySession())
    result = run_connectivity_test(10808, urls=["http://bad", "http://good"], timeout=5)

    assert result.ok is True
    assert result.url == "http://good"
    assert calls == ["http://bad", "http://good"]


def test_run_connectivity_test_all_urls_fail(monkeypatch):
    class AlwaysFailSession:
        def get(self, url, stream=True, timeout=None):
            raise requests.ConnectionError("down")

    monkeypatch.setattr("v2rm.net.speedtest.build_proxy_session", lambda port, auth=None: AlwaysFailSession())
    result = run_connectivity_test(10808, urls=["http://a", "http://b"], timeout=5)

    assert result.ok is False
    assert result.error


def test_run_connectivity_test_passes_the_proxy_login_to_the_session(monkeypatch):
    from v2rm.models.auth import ProxyAuth

    seen = {}

    class OkSession:
        def get(self, url, stream=True, timeout=None):
            return FakeStreamResponse([b"ok-data"])

    def build(port, auth=None):
        seen["port"], seen["auth"] = port, auth
        return OkSession()

    monkeypatch.setattr("v2rm.net.speedtest.build_proxy_session", build)
    auth = ProxyAuth("demo", "demo-pass")
    assert run_connectivity_test(10808, urls=["http://good"], timeout=5, auth=auth).ok is True
    assert seen == {"port": 10808, "auth": auth}
