"""Xray-core publishes its newest builds only as GitHub pre-releases, which GitHub's
"latest" endpoint never returns -- so the installer has to be able to ask for them."""

from __future__ import annotations

import hashlib
import io
import zipfile

import pytest
import requests

from v2rm.coredl import github
from v2rm.coredl import install as installer
from v2rm.errors import DownloadError


class FakeResponse:
    def __init__(self, status_code=200, json_data=None, content=b""):
        self.status_code = status_code
        self._json_data = json_data
        self.content = content
        self.text = content.decode("utf-8", errors="replace") if isinstance(content, bytes) else str(content)

    def json(self):
        return self._json_data


def release_json(tag, prerelease=False, draft=False, size=21_000_000, digest=None):
    asset = {"name": "Xray-linux-64.zip", "browser_download_url": f"http://example/{tag}/Xray-linux-64.zip", "size": size}
    if digest:
        asset["digest"] = digest
    return {"tag_name": tag, "prerelease": prerelease, "draft": draft, "assets": [asset]}


def zip_bytes():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("xray", b"FAKE-XRAY-BINARY")
    return buf.getvalue()


# ---- picking the newest release ---------------------------------------------------------------------------------


def test_newest_release_prefers_the_highest_version_not_the_first_or_the_stable_one():
    items = [
        release_json("v26.9.30", prerelease=True),
        release_json("v26.10.17", prerelease=True),  # highest, though listed second
        release_json("v26.3.27"),
    ]
    assert github.newest_release(items)["tag_name"] == "v26.10.17"


def test_newest_release_compares_numbers_not_text():
    items = [release_json("v26.9.9", prerelease=True), release_json("v26.10.1", prerelease=True)]
    assert github.newest_release(items)["tag_name"] == "v26.10.1"


def test_newest_release_skips_drafts_and_prefers_stable_on_a_tie():
    items = [release_json("v27.0.0", draft=True), release_json("v26.10.17", prerelease=True), release_json("v26.10.17")]
    chosen = github.newest_release(items)
    assert chosen["tag_name"] == "v26.10.17" and not chosen["prerelease"]


def test_newest_release_with_nothing_usable_is_an_error():
    with pytest.raises(DownloadError, match="no releases"):
        github.newest_release([])
    with pytest.raises(DownloadError, match="no releases"):
        github.newest_release([release_json("v1.0.0", draft=True)])


# ---- fetching -----------------------------------------------------------------------------------------------------


def test_include_prerelease_asks_for_the_release_list_and_returns_the_newest(monkeypatch):
    seen = []

    def fake_get(url, headers=None, timeout=None):
        seen.append(url)
        return FakeResponse(200, [release_json("v26.3.27"), release_json("v26.10.17", prerelease=True)])

    monkeypatch.setattr(requests, "get", fake_get)
    release = github.fetch_xray_release(include_prerelease=True)
    assert seen == ["https://api.github.com/repos/XTLS/Xray-core/releases?per_page=6"]
    assert release.tag == "v26.10.17" and release.prerelease is True
    assert release.find("Xray-linux-64.zip").size == 21_000_000


def test_a_specific_version_wins_over_include_prerelease_and_may_be_a_prerelease(monkeypatch):
    seen = []

    def fake_get(url, headers=None, timeout=None):
        seen.append(url)
        return FakeResponse(200, release_json("v26.9.30", prerelease=True))

    monkeypatch.setattr(requests, "get", fake_get)
    release = github.fetch_xray_release("v26.9.30", include_prerelease=True)
    assert seen == ["https://api.github.com/repos/XTLS/Xray-core/releases/tags/v26.9.30"]
    assert release.prerelease is True


def test_the_default_is_still_githubs_latest_which_skips_prereleases(monkeypatch):
    seen = []

    def fake_get(url, headers=None, timeout=None):
        seen.append(url)
        return FakeResponse(200, release_json("v26.3.27"))

    monkeypatch.setattr(requests, "get", fake_get)
    assert github.fetch_xray_release().prerelease is False
    assert seen == ["https://api.github.com/repos/XTLS/Xray-core/releases/latest"]


def test_singbox_can_ask_for_prereleases_too(monkeypatch):
    seen = []
    monkeypatch.setattr(
        requests, "get",
        lambda url, headers=None, timeout=None: (seen.append(url), FakeResponse(200, [release_json("v1.13.0-beta.3", prerelease=True)]))[1],
    )
    assert github.fetch_singbox_release(include_prerelease=True).tag == "v1.13.0-beta.3"
    assert seen == ["https://api.github.com/repos/SagerNet/sing-box/releases?per_page=6"]


# ---- installing ---------------------------------------------------------------------------------------------------


def test_install_announces_the_download_with_its_size(monkeypatch):
    data = zip_bytes()
    listing = [release_json("v26.10.17", prerelease=True, size=20_700_000, digest="sha256:" + hashlib.sha256(data).hexdigest())]

    def fake_get(url, headers=None, timeout=None):
        if "api.github.com" in url:
            return FakeResponse(200, listing)
        return FakeResponse(200, content=data)

    monkeypatch.setattr(requests, "get", fake_get)
    monkeypatch.setattr(github.platform, "machine", lambda: "x86_64")
    messages: list[str] = []

    tag = installer.install_xray(include_prerelease=True, progress=messages.append)

    assert tag == "v26.10.17"
    assert installer.current_version("xray") == "v26.10.17"
    assert messages == ["Downloading Xray-linux-64.zip (20.7 MB) -- this can take a while on a slow connection..."]


def test_install_without_a_known_size_still_announces(monkeypatch):
    data = zip_bytes()
    release = github.Release(
        tag="v1.0.0",
        assets=[github.ReleaseAsset("Xray-linux-64.zip", "http://example/x.zip", digest="sha256:" + hashlib.sha256(data).hexdigest())],
    )
    monkeypatch.setattr(requests, "get", lambda url, headers=None, timeout=None: FakeResponse(200, content=data))
    monkeypatch.setattr(github.platform, "machine", lambda: "x86_64")
    messages: list[str] = []
    installer.install_xray(release=release, progress=messages.append)
    assert messages == ["Downloading Xray-linux-64.zip -- this can take a while on a slow connection..."]


def test_install_with_an_already_fetched_release_does_not_ask_github_again(monkeypatch):
    data = zip_bytes()
    release = github.Release(
        tag="v26.10.17",
        assets=[github.ReleaseAsset("Xray-linux-64.zip", "http://example/x.zip", digest="sha256:" + hashlib.sha256(data).hexdigest())],
    )

    def fake_get(url, headers=None, timeout=None):
        assert "api.github.com" not in url, "the release was already fetched"
        return FakeResponse(200, content=data)

    monkeypatch.setattr(requests, "get", fake_get)
    monkeypatch.setattr(github.platform, "machine", lambda: "x86_64")
    assert installer.install_xray(release=release) == "v26.10.17"


def test_a_corrupt_download_is_still_rejected_for_a_prerelease(monkeypatch):
    release = github.Release(
        tag="v26.10.17",
        assets=[github.ReleaseAsset("Xray-linux-64.zip", "http://example/x.zip", digest="sha256:" + "0" * 64)],
    )
    monkeypatch.setattr(requests, "get", lambda url, headers=None, timeout=None: FakeResponse(200, content=zip_bytes()))
    monkeypatch.setattr(github.platform, "machine", lambda: "x86_64")
    from v2rm.errors import ChecksumError

    with pytest.raises(ChecksumError):
        installer.install_xray(release=release)
    assert installer.current_version("xray") is None
