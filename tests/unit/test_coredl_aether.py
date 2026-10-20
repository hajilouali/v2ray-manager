"""Installing Aether: picking the right release asset, verifying it, and unpacking the binary
together with the `pt/` helper programs it expects beside itself."""

from __future__ import annotations

import hashlib
import io
import tarfile

import pytest
import requests
from typer.testing import CliRunner

from v2rm.cli.app import app
from v2rm.coredl import github
from v2rm.coredl import install as installer
from v2rm.errors import ChecksumError, DownloadError
from v2rm.store import paths

runner = CliRunner()

ASSET = "aether-linux-x86_64-musl.tar.gz"


class FakeResponse:
    def __init__(self, status_code=200, json_data=None, content=b""):
        self.status_code = status_code
        self._json_data = json_data
        self.content = content
        self.text = content.decode("utf-8", errors="replace") if isinstance(content, bytes) else str(content)

    def json(self):
        return self._json_data


def archive(members: dict[str, bytes | None], modes: dict[str, int] | None = None) -> bytes:
    """A .tar.gz with the given members (None = a directory)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, content in members.items():
            info = tarfile.TarInfo(name=name)
            if content is None:
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                tf.addfile(info)
                continue
            info.size = len(content)
            info.mode = (modes or {}).get(name, 0o644)
            tf.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def aether_archive() -> bytes:
    return archive(
        {
            "aether": b"FAKE-AETHER",
            "pt/": None,
            "pt/psiphon-tunnel-core": b"FAKE-PSIPHON",
            "pt/lyrebird": b"FAKE-LYREBIRD",
            "README.txt": b"not wanted",
        },
        modes={"aether": 0o755, "pt/psiphon-tunnel-core": 0o755},
    )


# ---- choosing the asset ---------------------------------------------------------------------------


def test_default_asset_is_the_static_musl_build_for_the_cpu():
    assert github.aether_asset_name("x86_64") == "aether-linux-x86_64-musl.tar.gz"
    assert github.aether_asset_name("aarch64") == "aether-linux-aarch64-musl.tar.gz"
    assert github.aether_asset_name("arm64") == "aether-linux-aarch64-musl.tar.gz"
    assert github.aether_asset_name("armv7l") == "aether-linux-armv7-musl.tar.gz"


def test_the_glibc_build_can_be_asked_for():
    assert github.aether_asset_name("x86_64", "gnu") == "aether-linux-x86_64.tar.gz"
    assert github.aether_asset_name("aarch64", "gnu") == "aether-linux-arm64.tar.gz"
    assert github.aether_asset_name("armv7l", "GNU") == "aether-linux-armv7.tar.gz"


def test_unknown_cpu_or_variant_is_an_error():
    with pytest.raises(DownloadError, match="architecture"):
        github.aether_asset_name("sparc64")
    with pytest.raises(DownloadError, match="variant"):
        github.aether_asset_name("x86_64", "uclibc")


# ---- unpacking ------------------------------------------------------------------------------------


def test_the_binary_and_the_pt_folder_are_unpacked_and_nothing_else(tmp_path):
    dest = tmp_path / "v"
    installer._extract_tar_tree(aether_archive(), "aether", dest)

    assert (dest / "aether").read_bytes() == b"FAKE-AETHER"
    assert (dest / "pt" / "psiphon-tunnel-core").read_bytes() == b"FAKE-PSIPHON"
    assert (dest / "pt" / "lyrebird").exists()
    assert not (dest / "README.txt").exists()


@pytest.mark.skipif(not hasattr(__import__("os"), "geteuid"), reason="POSIX permission bits")
def test_unpacked_programs_are_executable(tmp_path):
    dest = tmp_path / "v"
    installer._extract_tar_tree(aether_archive(), "aether", dest)
    assert (dest / "aether").stat().st_mode & 0o100
    assert (dest / "pt" / "psiphon-tunnel-core").stat().st_mode & 0o100


def test_a_wrapper_folder_around_the_archive_is_tolerated(tmp_path):
    data = archive({"aether-linux/aether": b"BIN", "aether-linux/pt/helper": b"H"})
    installer._extract_tar_tree(data, "aether", tmp_path / "v")
    assert (tmp_path / "v" / "aether").read_bytes() == b"BIN"
    assert (tmp_path / "v" / "pt" / "helper").read_bytes() == b"H"


def test_members_that_climb_out_of_the_folder_are_ignored(tmp_path):
    data = archive({"aether": b"BIN", "../evil": b"X", "pt/../../evil2": b"Y", "/abs/evil3": b"Z"})
    installer._extract_tar_tree(data, "aether", tmp_path / "v")
    assert (tmp_path / "v" / "aether").exists()
    assert not (tmp_path / "evil").exists() and not (tmp_path / "evil2").exists()


def test_symlinks_are_not_unpacked(tmp_path):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo(name="aether")
        info.size = 3
        tf.addfile(info, io.BytesIO(b"BIN"))
        link = tarfile.TarInfo(name="pt/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        tf.addfile(link)
    installer._extract_tar_tree(buf.getvalue(), "aether", tmp_path / "v")
    assert not (tmp_path / "v" / "pt" / "link").exists()


def test_an_archive_without_the_binary_is_an_error(tmp_path):
    with pytest.raises(DownloadError, match="did not contain"):
        installer._extract_tar_tree(archive({"pt/helper": b"H"}), "aether", tmp_path / "v")


# ---- the checksum sidecar -------------------------------------------------------------------------


def release_with(data: bytes, digest: str | None = None, sidecar: bytes | None = None) -> github.Release:
    assets = [github.ReleaseAsset(name=ASSET, download_url="http://example/a.tar.gz", digest=digest)]
    if sidecar is not None:
        assets.append(github.ReleaseAsset(name=f"{ASSET}.sha256", download_url="http://example/a.sha256"))
    return github.Release(tag="v2.3.0", assets=assets)


def test_sidecar_checksum_is_verified(monkeypatch):
    data = b"payload"
    sha = hashlib.sha256(data).hexdigest()
    monkeypatch.setattr(requests, "get", lambda url, **k: FakeResponse(200, content=f"{sha}  {ASSET}\n".encode()))
    release = release_with(data, sidecar=b"x")
    assert installer._verify_sha256_sidecar(data, release.assets[0], release) is True


def test_sidecar_mismatch_raises(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda url, **k: FakeResponse(200, content=("0" * 64).encode()))
    release = release_with(b"payload", sidecar=b"x")
    with pytest.raises(ChecksumError):
        installer._verify_sha256_sidecar(b"payload", release.assets[0], release)


def test_no_sidecar_means_nothing_was_verified():
    release = release_with(b"payload")
    assert installer._verify_sha256_sidecar(b"payload", release.assets[0], release) is False


# ---- end to end -----------------------------------------------------------------------------------


def fake_network(monkeypatch, data: bytes, with_digest=True, with_sidecar=False):
    sha = hashlib.sha256(data).hexdigest()
    asset = {"name": ASSET, "browser_download_url": "http://example/a.tar.gz", "size": len(data)}
    if with_digest:
        asset["digest"] = f"sha256:{sha}"
    assets = [asset]
    if with_sidecar:
        assets.append({"name": f"{ASSET}.sha256", "browser_download_url": "http://example/a.sha256"})

    def fake_get(url, headers=None, timeout=None):
        if "api.github.com" in url:
            return FakeResponse(200, {"tag_name": "v2.3.0", "assets": assets})
        if url == "http://example/a.tar.gz":
            return FakeResponse(200, content=data)
        if url == "http://example/a.sha256":
            return FakeResponse(200, content=f"{sha}  {ASSET}\n".encode())
        raise AssertionError(f"unexpected URL {url}")

    monkeypatch.setattr(requests, "get", fake_get)
    monkeypatch.setattr(github.platform, "machine", lambda: "x86_64")


def test_install_aether_end_to_end(monkeypatch):
    fake_network(monkeypatch, aether_archive())

    tag = installer.install_aether()

    assert tag == "v2.3.0"
    assert installer.current_version("aether") == "v2.3.0"
    binary = paths.engine_binary_path("aether")
    assert binary.read_bytes() == b"FAKE-AETHER"
    assert (binary.parent / "pt" / "psiphon-tunnel-core").exists()
    assert installer.stored_aether_variant() == "musl"


def test_install_aether_accepts_a_sidecar_when_github_gives_no_digest(monkeypatch):
    fake_network(monkeypatch, aether_archive(), with_digest=False, with_sidecar=True)
    assert installer.install_aether() == "v2.3.0"


def test_install_aether_refuses_a_release_with_no_checksum_at_all(monkeypatch):
    fake_network(monkeypatch, aether_archive(), with_digest=False, with_sidecar=False)
    with pytest.raises(ChecksumError, match="no checksum"):
        installer.install_aether()
    assert installer.current_version("aether") is None


def test_install_aether_refuses_a_tampered_download(monkeypatch):
    data = aether_archive()
    fake_network(monkeypatch, data)
    monkeypatch.setattr(
        requests,
        "get",
        lambda url, **k: FakeResponse(
            200,
            {
                "tag_name": "v2.3.0",
                "assets": [
                    {"name": ASSET, "browser_download_url": "http://example/a.tar.gz", "digest": "sha256:" + "0" * 64}
                ],
            }
            if "api.github.com" in url
            else None,
            content=data,
        ),
    )
    with pytest.raises(ChecksumError):
        installer.install_aether()
    assert installer.current_version("aether") is None


def test_the_chosen_variant_is_remembered_for_updates(monkeypatch):
    gnu = "aether-linux-x86_64.tar.gz"
    data = aether_archive()
    sha = hashlib.sha256(data).hexdigest()

    def fake_get(url, headers=None, timeout=None):
        if "api.github.com" in url:
            return FakeResponse(
                200,
                {
                    "tag_name": "v2.3.0",
                    "assets": [{"name": gnu, "browser_download_url": "http://example/g", "digest": f"sha256:{sha}"}],
                },
            )
        return FakeResponse(200, content=data)

    monkeypatch.setattr(requests, "get", fake_get)
    monkeypatch.setattr(github.platform, "machine", lambda: "x86_64")

    installer.install_aether(variant="gnu")
    assert installer.stored_aether_variant() == "gnu"
    installer.install_aether()  # an update with no variant keeps the one in use
    assert installer.stored_aether_variant() == "gnu"


# ---- the `core` commands --------------------------------------------------------------------------


def test_core_list_includes_aether_but_never_marks_it_active():
    result = runner.invoke(app, ["core", "list"])
    assert result.exit_code == 0, result.output
    assert "aether" in result.output


def test_core_use_refuses_aether():
    result = runner.invoke(app, ["core", "use", "aether"])
    assert result.exit_code != 0
    assert "only runs Aether profiles" in str(result.exception)


def test_variant_only_applies_to_aether():
    result = runner.invoke(app, ["core", "install", "xray", "--variant", "gnu"])
    assert result.exit_code != 0
    assert "only applies to aether" in str(result.exception)
    result = runner.invoke(app, ["core", "install", "aether", "--variant", "uclibc"])
    assert result.exit_code != 0
    assert "Unknown --variant" in str(result.exception)


def test_core_install_aether_through_the_command(monkeypatch):
    fake_network(monkeypatch, aether_archive())
    result = runner.invoke(app, ["core", "install", "aether"])
    assert result.exit_code == 0, result.output
    assert "Installed aether v2.3.0" in result.output
    assert installer.current_version("aether") == "v2.3.0"


def test_version_command_lists_aether():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "aether" in result.output


# ---- installing from a file you already have --------------------------------------------------------


def test_install_from_a_local_archive_with_a_checksum(tmp_path):
    data = aether_archive()
    archive_path = tmp_path / ASSET
    archive_path.write_bytes(data)

    tag, digest = installer.install_from_file("aether", archive_path, "v2.3.0", hashlib.sha256(data).hexdigest())

    assert tag == "v2.3.0" and digest == hashlib.sha256(data).hexdigest()
    assert installer.current_version("aether") == "v2.3.0"
    binary = paths.engine_binary_path("aether")
    assert binary.read_bytes() == b"FAKE-AETHER" and (binary.parent / "pt" / "lyrebird").exists()


def test_a_wrong_checksum_is_refused_and_nothing_is_installed(tmp_path):
    archive_path = tmp_path / ASSET
    archive_path.write_bytes(aether_archive())
    with pytest.raises(ChecksumError, match="mismatch"):
        installer.install_from_file("aether", archive_path, "v2.3.0", "0" * 64)
    assert installer.current_version("aether") is None


def test_a_version_and_an_existing_file_are_required(tmp_path):
    with pytest.raises(DownloadError, match="not found"):
        installer.install_from_file("aether", tmp_path / "nope.tar.gz", "v2.3.0")
    archive_path = tmp_path / ASSET
    archive_path.write_bytes(aether_archive())
    with pytest.raises(DownloadError, match="--version is required"):
        installer.install_from_file("aether", archive_path, " ")


def test_xray_and_singbox_can_be_installed_from_files_too(tmp_path):
    import zipfile

    zip_path = tmp_path / "Xray-linux-64.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("xray", b"FAKE-XRAY")
    installer.install_from_file("xray", zip_path, "v26.10.17")
    assert paths.engine_binary_path("xray").read_bytes() == b"FAKE-XRAY"

    tar_path = tmp_path / "sing-box.tar.gz"
    tar_path.write_bytes(archive({"sing-box-1.14.0-linux-amd64/sing-box": b"FAKE-SINGBOX"}))
    installer.install_from_file("singbox", tar_path, "v1.14.0")
    assert paths.engine_binary_path("singbox").read_bytes() == b"FAKE-SINGBOX"


def test_core_install_from_file_through_the_command(tmp_path):
    data = aether_archive()
    archive_path = tmp_path / ASSET
    archive_path.write_bytes(data)

    result = runner.invoke(
        app,
        ["core", "install", "aether", "--from-file", str(archive_path), "--version", "v2.3.0",
         "--sha256", hashlib.sha256(data).hexdigest()],
    )
    assert result.exit_code == 0, result.output
    assert "Installed aether v2.3.0" in result.output and "Nothing verified" not in result.output
    assert installer.current_version("aether") == "v2.3.0"


def test_without_a_checksum_the_command_says_nothing_verified_the_file(tmp_path):
    archive_path = tmp_path / ASSET
    archive_path.write_bytes(aether_archive())
    result = runner.invoke(app, ["core", "install", "aether", "--from-file", str(archive_path), "--version", "v2.3.0"])
    assert result.exit_code == 0, result.output
    assert "Nothing verified this file" in result.output and "sha256 " in result.output


def test_from_file_option_mistakes(tmp_path):
    archive_path = tmp_path / ASSET
    archive_path.write_bytes(aether_archive())
    for args, fragment in [
        (["--sha256", "ab" * 32], "goes with --from-file"),
        (["--from-file", str(archive_path), "--pre"], "doesn't apply"),
        (["--from-file", str(archive_path)], "--version is required"),
    ]:
        result = runner.invoke(app, ["core", "install", "aether", *args])
        assert result.exit_code != 0 and fragment in str(result.exception), (args, str(result.exception))
