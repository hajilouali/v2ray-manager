from __future__ import annotations

import hashlib
import io
import zipfile

import pytest
import requests
from typer.testing import CliRunner

from v2rm.cli.app import app
from v2rm.coredl import github
from v2rm.coredl import install as installer
from v2rm.store import paths

runner = CliRunner()


class FakeResponse:
    def __init__(self, status_code=200, json_data=None, content=b""):
        self.status_code, self._json, self.content = status_code, json_data, content
        self.text = content.decode("utf-8", errors="replace") if isinstance(content, bytes) else str(content)

    def json(self):
        return self._json


@pytest.fixture
def xray_releases(monkeypatch):
    """A fake GitHub: stable v26.3.27, pre-releases v26.9.30 and v26.10.17. Returns the list of requested URLs."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("xray", b"FAKE-XRAY")
    data = buf.getvalue()
    digest = "sha256:" + hashlib.sha256(data).hexdigest()

    def release(tag, prerelease):
        return {
            "tag_name": tag, "prerelease": prerelease, "draft": False,
            "assets": [{"name": "Xray-linux-64.zip", "browser_download_url": f"http://example/{tag}.zip", "size": 21_000_000, "digest": digest}],
        }

    stable = release("v26.3.27", False)
    listing = [release("v26.10.17", True), release("v26.9.30", True), stable]
    requested: list[str] = []

    def fake_get(url, headers=None, timeout=None):
        requested.append(url)
        if url.endswith("/releases/latest"):
            return FakeResponse(200, stable)
        if "/releases?per_page=" in url:
            return FakeResponse(200, listing)
        if "/releases/tags/" in url:
            tag = url.rsplit("/", 1)[-1]
            return FakeResponse(200, next(r for r in listing if r["tag_name"] == tag))
        return FakeResponse(200, content=data)

    monkeypatch.setattr(requests, "get", fake_get)
    monkeypatch.setattr(github.platform, "machine", lambda: "x86_64")
    return requested


def install_old(tag, content=b"old"):
    installer._install_binary("xray", tag, content)
    installer.use_version("xray", tag)


def test_install_without_pre_gets_the_latest_stable(xray_releases):
    result = runner.invoke(app, ["core", "install", "xray"])
    assert result.exit_code == 0, result.output
    assert installer.current_version("xray") == "v26.3.27"
    assert "Downloading Xray-linux-64.zip (21.0 MB)" in result.output


def test_install_with_pre_gets_the_newest_release_and_says_it_is_a_prerelease(xray_releases):
    result = runner.invoke(app, ["core", "install", "xray", "--pre"])
    assert result.exit_code == 0, result.output
    assert installer.current_version("xray") == "v26.10.17"
    assert "Release: v26.10.17 (pre-release)" in result.output
    assert paths.engine_binary_path("xray").read_bytes() == b"FAKE-XRAY"


def test_install_a_specific_prerelease_tag(xray_releases):
    assert runner.invoke(app, ["core", "install", "xray", "--version", "v26.9.30"]).exit_code == 0
    assert installer.current_version("xray") == "v26.9.30"


def test_version_and_pre_together_are_rejected(xray_releases):
    result = runner.invoke(app, ["core", "install", "xray", "--version", "v26.9.30", "--pre"])
    assert result.exit_code != 0
    assert "either --version or --pre" in str(result.exception)
    assert installer.current_version("xray") is None


def test_update_installs_a_newer_stable(xray_releases):
    install_old("v26.1.1")
    result = runner.invoke(app, ["core", "update", "xray"])
    assert result.exit_code == 0, result.output
    assert "Updated xray v26.1.1 -> v26.3.27" in result.output


def test_update_with_pre_moves_to_the_newest_prerelease(xray_releases):
    install_old("v26.3.27")
    result = runner.invoke(app, ["core", "update", "xray", "--pre"])
    assert result.exit_code == 0, result.output
    assert "Updated xray v26.3.27 -> v26.10.17" in result.output
    assert installer.current_version("xray") == "v26.10.17"


def test_update_never_downgrades_to_an_older_stable(xray_releases):
    install_old("v26.10.17", b"newer prerelease")
    result = runner.invoke(app, ["core", "update", "xray"])
    assert result.exit_code == 0, result.output
    assert "newer than the latest stable release (v26.3.27); nothing to do" in result.output
    assert "Add --pre" in result.output
    assert installer.current_version("xray") == "v26.10.17"  # untouched
    assert paths.engine_binary_path("xray").read_bytes() == b"newer prerelease"
    assert not any(url.endswith(".zip") for url in xray_releases)  # and nothing was downloaded


def test_update_when_already_current(xray_releases):
    install_old("v26.10.17")
    result = runner.invoke(app, ["core", "update", "xray", "--pre"])
    assert "already up to date (v26.10.17)" in result.output
    assert not any(url.endswith(".zip") for url in xray_releases)


def test_update_with_nothing_installed_installs(xray_releases):
    result = runner.invoke(app, ["core", "update", "xray", "--pre"])
    assert result.exit_code == 0, result.output
    assert "Updated xray (none) -> v26.10.17" in result.output


def test_help_explains_why_pre_exists():
    for command in ("install", "update"):
        output = runner.invoke(app, ["core", command, "--help"]).output
        assert "--pre" in output and "pre-releases" in output
