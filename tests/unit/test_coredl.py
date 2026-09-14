from __future__ import annotations

import hashlib
import io
import tarfile
import zipfile

import pytest
import requests

from v2rm.coredl import github
from v2rm.coredl import install as installer
from v2rm.errors import ChecksumError, DownloadError
from v2rm.store import paths


class FakeResponse:
    def __init__(self, status_code=200, json_data=None, content=b""):
        self.status_code = status_code
        self._json_data = json_data
        self.content = content
        self.text = content.decode("utf-8", errors="replace") if isinstance(content, bytes) else str(content)

    def json(self):
        return self._json_data


def test_xray_asset_name_maps_known_architectures():
    assert github.xray_asset_name("x86_64") == "Xray-linux-64.zip"
    assert github.xray_asset_name("aarch64") == "Xray-linux-arm64-v8a.zip"


def test_xray_asset_name_unknown_architecture_raises():
    with pytest.raises(DownloadError):
        github.xray_asset_name("sparc64")


def test_singbox_asset_name_strips_v_prefix():
    assert github.singbox_asset_name("v1.14.0", "x86_64") == "sing-box-1.14.0-linux-amd64.tar.gz"
    assert github.singbox_asset_name("v1.14.0", "aarch64") == "sing-box-1.14.0-linux-arm64.tar.gz"


def test_release_find_by_name():
    release = github.Release(tag="v1.0", assets=[github.ReleaseAsset(name="a.zip", download_url="http://x/a.zip")])
    assert release.find("a.zip") is not None
    assert release.find("missing") is None


def test_fetch_release_parses_response(monkeypatch):
    def fake_get(url, headers=None, timeout=None):
        assert "releases/latest" in url
        return FakeResponse(
            200,
            {
                "tag_name": "v9.9.9",
                "assets": [{"name": "Xray-linux-64.zip", "browser_download_url": "http://x/Xray-linux-64.zip"}],
            },
        )

    monkeypatch.setattr(requests, "get", fake_get)
    release = github.fetch_xray_release()
    assert release.tag == "v9.9.9"
    assert release.assets[0].name == "Xray-linux-64.zip"


def test_fetch_release_rate_limit_raises_clear_error(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(403, content=b"API rate limit exceeded"))
    with pytest.raises(DownloadError, match="rate limit"):
        github.fetch_xray_release()


def test_verify_digest_field_ok():
    data = b"hello world"
    asset = github.ReleaseAsset(name="x", download_url="u", digest=f"sha256:{hashlib.sha256(data).hexdigest()}")
    assert installer._verify_digest_field(data, asset) is True


def test_verify_digest_field_mismatch_raises():
    asset = github.ReleaseAsset(name="x", download_url="u", digest="sha256:" + "0" * 64)
    with pytest.raises(ChecksumError):
        installer._verify_digest_field(b"hello world", asset)


def test_verify_digest_field_absent_returns_false():
    asset = github.ReleaseAsset(name="x", download_url="u", digest=None)
    assert installer._verify_digest_field(b"data", asset) is False


def test_extract_zip_binary_finds_exact_basename():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("xray", b"BINARYDATA")
        zf.writestr("geoip.dat", b"notthebinary")
        zf.writestr("notxray", b"shouldnotmatch")
    content = installer._extract_zip_binary(buf.getvalue(), "xray")
    assert content == b"BINARYDATA"


def test_extract_zip_binary_missing_raises():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("readme.txt", b"nope")
    with pytest.raises(DownloadError):
        installer._extract_zip_binary(buf.getvalue(), "xray")


def test_extract_tar_binary_finds_exact_basename():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        data = b"SINGBOXBINARY"
        info = tarfile.TarInfo(name="sing-box-1.14.0-linux-amd64/sing-box")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    content = installer._extract_tar_binary(buf.getvalue(), "sing-box")
    assert content == b"SINGBOXBINARY"


def test_install_use_and_remove_version_lifecycle():
    installer._install_binary("xray", "v1.0.0", b"fake-binary-content")
    installer.use_version("xray", "v1.0.0")

    assert installer.installed_versions("xray") == ["v1.0.0"]
    assert installer.current_version("xray") == "v1.0.0"

    with pytest.raises(DownloadError):
        installer.remove_version("xray", "v1.0.0")  # active version can't be removed

    installer._install_binary("xray", "v1.1.0", b"fake-binary-content-2")
    installer.use_version("xray", "v1.1.0")
    assert installer.current_version("xray") == "v1.1.0"
    assert set(installer.installed_versions("xray")) == {"v1.0.0", "v1.1.0"}

    installer.remove_version("xray", "v1.0.0")
    assert installer.installed_versions("xray") == ["v1.1.0"]


def test_remove_nonexistent_version_raises():
    with pytest.raises(DownloadError):
        installer.remove_version("xray", "v0.0.0-does-not-exist")


def test_install_xray_end_to_end_with_mocked_network(monkeypatch):
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as zf:
        zf.writestr("xray", b"FAKE-XRAY-BINARY")
    zip_bytes = zip_buf.getvalue()

    def fake_get(url, headers=None, timeout=None):
        if "api.github.com" in url:
            return FakeResponse(
                200,
                {
                    "tag_name": "v26.3.27",
                    "assets": [
                        {"name": "Xray-linux-64.zip", "browser_download_url": "http://example/Xray-linux-64.zip"}
                    ],
                },
            )
        if url == "http://example/Xray-linux-64.zip":
            return FakeResponse(200, content=zip_bytes)
        raise AssertionError(f"unexpected URL {url}")

    monkeypatch.setattr(requests, "get", fake_get)
    monkeypatch.setattr(github.platform, "machine", lambda: "x86_64")

    tag = installer.install_xray()

    assert tag == "v26.3.27"
    assert installer.current_version("xray") == "v26.3.27"
    binary_path = paths.engine_binary_path("xray")
    assert binary_path.exists()
    assert binary_path.read_bytes() == b"FAKE-XRAY-BINARY"


def test_install_singbox_end_to_end_with_mocked_network(monkeypatch):
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w:gz") as tf:
        data = b"FAKE-SINGBOX-BINARY"
        info = tarfile.TarInfo(name="sing-box-1.14.0-linux-amd64/sing-box")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    tar_bytes = tar_buf.getvalue()

    def fake_get(url, headers=None, timeout=None):
        if "api.github.com" in url:
            return FakeResponse(
                200,
                {
                    "tag_name": "v1.14.0",
                    "assets": [
                        {
                            "name": "sing-box-1.14.0-linux-amd64.tar.gz",
                            "browser_download_url": "http://example/sing-box.tar.gz",
                        }
                    ],
                },
            )
        if url == "http://example/sing-box.tar.gz":
            return FakeResponse(200, content=tar_bytes)
        raise AssertionError(f"unexpected URL {url}")

    monkeypatch.setattr(requests, "get", fake_get)
    monkeypatch.setattr(github.platform, "machine", lambda: "x86_64")

    tag = installer.install_singbox()

    assert tag == "v1.14.0"
    binary_path = paths.engine_binary_path("singbox")
    assert binary_path.exists()
    assert binary_path.read_bytes() == b"FAKE-SINGBOX-BINARY"
