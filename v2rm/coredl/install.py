from __future__ import annotations

import hashlib
import io
import re
import shutil
import stat
import tarfile
import zipfile
from pathlib import Path

import requests

from v2rm.constants import DEFAULT_USER_AGENT, ENGINE_SINGBOX, ENGINE_XRAY
from v2rm.coredl.github import (
    Release,
    ReleaseAsset,
    fetch_singbox_release,
    fetch_xray_release,
    singbox_asset_name,
    xray_asset_name,
)
from v2rm.errors import ChecksumError, DownloadError
from v2rm.store import paths


def _download(url: str, timeout: float = 60.0) -> bytes:
    try:
        resp = requests.get(url, headers={"User-Agent": DEFAULT_USER_AGENT}, timeout=timeout)
    except requests.RequestException as exc:
        raise DownloadError(f"Download failed: {exc}") from exc
    if resp.status_code != 200:
        raise DownloadError(f"Download failed: HTTP {resp.status_code} for {url}")
    return resp.content


def _verify_digest_field(data: bytes, asset: ReleaseAsset) -> bool:
    """GitHub populates asset.digest ("sha256:...") for some repos/releases.
    Returns True if it verified the download, False if there was nothing to
    check (caller should then try a protocol-specific fallback)."""
    if not asset.digest or ":" not in asset.digest:
        return False
    algo, _, expected = asset.digest.partition(":")
    algo = algo.lower()
    if not hasattr(hashlib, algo):
        return False
    actual = hashlib.new(algo, data).hexdigest()
    if actual.lower() != expected.lower():
        raise ChecksumError(f"Checksum mismatch for {asset.name}: expected {expected}, got {actual}")
    return True


def _verify_xray_dgst(data: bytes, asset: ReleaseAsset, release: Release) -> bool:
    """Xray-core publishes a '<asset>.dgst' sidecar (OpenSSL-style multi-hash
    text) alongside every release asset; verify against its SHA256 line."""
    dgst_asset = release.find(f"{asset.name}.dgst")
    if dgst_asset is None:
        return False
    dgst_text = _download(dgst_asset.download_url).decode("utf-8", errors="replace")
    match = re.search(r"SHA256\([^)]*\)\s*=\s*([0-9a-fA-F]{64})", dgst_text)
    if not match:
        return False
    expected = match.group(1).lower()
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise ChecksumError(f"Checksum mismatch for {asset.name}: expected {expected}, got {actual}")
    return True


def _extract_zip_binary(data: bytes, binary_name: str) -> bytes:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for name in zf.namelist():
            if name.rsplit("/", 1)[-1] == binary_name:
                return zf.read(name)
    raise DownloadError(f"Archive did not contain a file named '{binary_name}'")


def _extract_tar_binary(data: bytes, binary_name: str) -> bytes:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        for member in tf.getmembers():
            if member.isfile() and member.name.rsplit("/", 1)[-1] == binary_name:
                extracted = tf.extractfile(member)
                if extracted is not None:
                    return extracted.read()
    raise DownloadError(f"Archive did not contain a file named '{binary_name}'")


def _install_binary(engine: str, version: str, binary_bytes: bytes) -> Path:
    binary_name = "xray" if engine == ENGINE_XRAY else "sing-box"
    version_dir = paths.engine_dir(engine) / version
    version_dir.mkdir(parents=True, exist_ok=True)
    binary_path = version_dir / binary_name
    binary_path.write_bytes(binary_bytes)
    mode = binary_path.stat().st_mode
    binary_path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return binary_path


def use_version(engine: str, version: str) -> None:
    version_dir = paths.engine_dir(engine) / version
    if not version_dir.exists():
        raise DownloadError(f"{engine} version '{version}' is not installed")

    current_link = paths.engine_current_link(engine)
    if current_link.exists() or current_link.is_symlink():
        if current_link.is_symlink() or current_link.is_file():
            current_link.unlink()
        else:
            shutil.rmtree(current_link)
    try:
        current_link.symlink_to(version_dir, target_is_directory=True)
    except OSError:
        # Creating symlinks needs elevated privileges/Developer Mode on
        # Windows dev machines; a plain copy is functionally equivalent for
        # our purposes since "current" is only ever read, never written.
        shutil.copytree(version_dir, current_link)

    paths.engine_current_version_file(engine).write_text(version, encoding="utf-8")


def current_version(engine: str) -> str | None:
    marker = paths.engine_current_version_file(engine)
    if marker.exists():
        return marker.read_text(encoding="utf-8").strip()
    return None


def installed_versions(engine: str) -> list[str]:
    engine_dir = paths.engine_dir(engine)
    if not engine_dir.exists():
        return []
    return sorted(p.name for p in engine_dir.iterdir() if p.is_dir() and p.name != "current")


def remove_version(engine: str, version: str) -> None:
    version_dir = paths.engine_dir(engine) / version
    if not version_dir.exists():
        raise DownloadError(f"{engine} version '{version}' is not installed")
    if current_version(engine) == version:
        raise DownloadError(
            f"Cannot remove {engine} {version}: it is the active version. Switch first with `v2rm core use`."
        )
    shutil.rmtree(version_dir)


def install_xray(version: str | None = None) -> str:
    release = fetch_xray_release(version)
    asset_name = xray_asset_name()
    asset = release.find(asset_name)
    if asset is None:
        raise DownloadError(f"Release {release.tag} has no asset named '{asset_name}'")

    data = _download(asset.download_url)
    if not _verify_digest_field(data, asset):
        _verify_xray_dgst(data, asset, release)

    binary_bytes = _extract_zip_binary(data, "xray")
    _install_binary(ENGINE_XRAY, release.tag, binary_bytes)
    use_version(ENGINE_XRAY, release.tag)
    return release.tag


def install_singbox(version: str | None = None) -> str:
    release = fetch_singbox_release(version)
    asset_name = singbox_asset_name(release.tag)
    asset = release.find(asset_name)
    if asset is None:
        raise DownloadError(f"Release {release.tag} has no asset named '{asset_name}'")

    data = _download(asset.download_url)
    _verify_digest_field(data, asset)

    binary_bytes = _extract_tar_binary(data, "sing-box")
    _install_binary(ENGINE_SINGBOX, release.tag, binary_bytes)
    use_version(ENGINE_SINGBOX, release.tag)
    return release.tag
