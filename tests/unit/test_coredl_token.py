"""GitHub's anonymous API quota is 60 requests an hour per IP -- found when a real server's quota ran out."""

from __future__ import annotations

import time

import pytest
import requests

from v2rm.coredl import github
from v2rm.errors import DownloadError


class FakeResponse:
    def __init__(self, status_code=200, json_data=None, text="", headers=None):
        self.status_code, self._json, self.text = status_code, json_data, text
        self.headers = headers or {}

    def json(self):
        return self._json


@pytest.fixture(autouse=True)
def _no_token_in_the_environment(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)


def capture(monkeypatch, response=None):
    seen = {}

    def fake_get(url, headers=None, timeout=None):
        seen["url"], seen["headers"] = url, headers
        return response or FakeResponse(200, {"tag_name": "v1.0.0", "assets": []})

    monkeypatch.setattr(requests, "get", fake_get)
    return seen


def test_no_token_means_no_authorization_header(monkeypatch):
    seen = capture(monkeypatch)
    github.fetch_xray_release()
    assert "Authorization" not in seen["headers"]
    assert seen["headers"]["User-Agent"].startswith("v2rm/")


@pytest.mark.parametrize("variable", ["GITHUB_TOKEN", "GH_TOKEN"])
def test_a_token_in_the_environment_is_sent_to_the_api(monkeypatch, variable):
    monkeypatch.setenv(variable, "  ghp_exampletoken  ")
    seen = capture(monkeypatch)
    github.fetch_xray_release()
    assert seen["url"].startswith("https://api.github.com/")
    assert seen["headers"]["Authorization"] == "Bearer ghp_exampletoken"


def test_github_token_wins_over_gh_token(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "first")
    monkeypatch.setenv("GH_TOKEN", "second")
    seen = capture(monkeypatch)
    github.fetch_xray_release()
    assert seen["headers"]["Authorization"] == "Bearer first"


def test_the_token_is_never_sent_with_asset_downloads(monkeypatch):
    from v2rm.coredl import install

    monkeypatch.setenv("GITHUB_TOKEN", "secret-token")
    seen = {}
    response = FakeResponse(200)
    response.content = b"zip"

    def fake_get(url, headers=None, timeout=None):
        seen["headers"] = headers
        return response

    monkeypatch.setattr(requests, "get", fake_get)
    install._download("https://github.com/XTLS/Xray-core/releases/download/v1/Xray-linux-64.zip")
    assert "Authorization" not in seen["headers"]


def test_the_rate_limit_message_says_when_it_resets_and_how_to_get_more(monkeypatch):
    reset = int(time.time()) + 8 * 60
    capture(monkeypatch, FakeResponse(403, text='{"message":"API rate limit exceeded for 1.2.3.4"}', headers={"X-RateLimit-Reset": str(reset)}))
    with pytest.raises(DownloadError) as err:
        github.fetch_xray_release()
    message = str(err.value)
    assert "rate limit exceeded" in message and "60 requests an hour per IP" in message
    assert "resets in about 9 min" in message  # 8 min and a bit, rounded up
    assert "GITHUB_TOKEN" in message


def test_the_rate_limit_message_without_a_reset_header(monkeypatch):
    capture(monkeypatch, FakeResponse(403, text="API rate limit exceeded"))
    with pytest.raises(DownloadError) as err:
        github.fetch_xray_release()
    assert "resets in" not in str(err.value) and "GITHUB_TOKEN" in str(err.value)


def test_a_forbidden_that_is_not_a_rate_limit_is_reported_as_it_was(monkeypatch):
    capture(monkeypatch, FakeResponse(403, text="Request forbidden by administrative rules."))
    with pytest.raises(DownloadError, match="HTTP 403"):
        github.fetch_xray_release()
