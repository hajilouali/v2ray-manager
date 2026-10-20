from __future__ import annotations

import hashlib
import io
import re
import shutil
import stat
import tarfile
import zipfile
from collections.abc import Callable
from pathlib import Path, PurePosixPath

import requests

from v2rm.constants import DEFAULT_USER_AGENT, ENGINE_AETHER, ENGINE_SINGBOX, ENGINE_XRAY
from v2rm.coredl.github import (
    DEFAULT_AETHER_VARIANT,
    Release,
    ReleaseAsset,
    aether_asset_name,
    fetch_aether_release,
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


def _verify_sha256_sidecar(data: bytes, asset: ReleaseAsset, release: Release) -> bool:
    """A '<asset>.sha256' sidecar (sha256sum output: "<hex>  <name>"), as Aether publishes.
    Returns False if there is none; a mismatch raises."""
    sidecar = release.find(f"{asset.name}.sha256")
    if sidecar is None:
        return False
    text = _download(sidecar.download_url).decode("utf-8", errors="replace")
    match = re.search(r"\b([0-9a-fA-F]{64})\b", text)
    if not match:
        return False
    expected = match.group(1).lower()
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise ChecksumError(f"Checksum mismatch for {asset.name}: expected {expected}, got {actual}")
    return True


# Upper bounds for unpacking an archive we do not control: Aether's own is ~60 MB unpacked.
_MAX_MEMBER_BYTES = 300 * 1024 * 1024
_MAX_TOTAL_BYTES = 600 * 1024 * 1024


def _member_path(name: str) -> PurePosixPath | None:
    """The member's path inside the archive, or None if it is absolute or climbs out of it."""
    path = PurePosixPath(name.replace("\\", "/"))
    parts = [p for p in path.parts if p not in ("", ".")]
    if not parts or path.is_absolute() or ".." in parts:
        return None
    return PurePosixPath(*parts)


def _extract_tar_tree(data: bytes, binary_name: str, dest: Path, keep_dirs: tuple[str, ...] = ("pt",)) -> None:
    """Unpack `binary_name` and the `keep_dirs` folders from a .tar.gz into `dest`.

    Aether's archive is the program next to a `pt/` folder of helper programs (Tor and
    Psiphon transports) that it looks for beside itself, so a binary alone is not enough.
    Only regular files and directories are written: no links, no devices, nothing that
    would land outside `dest`."""
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        members = [(m, _member_path(m.name)) for m in tf.getmembers()]
        members = [(m, p) for m, p in members if p is not None]

        # Tolerate one wrapper folder around the whole archive.
        if members and not any(p == PurePosixPath(binary_name) for _, p in members):
            firsts = {p.parts[0] for _, p in members}
            if len(firsts) == 1:
                members = [(m, PurePosixPath(*p.parts[1:])) for m, p in members if len(p.parts) > 1]

        found = False
        total = 0
        for member, rel in members:
            top = rel.parts[0]
            is_binary = len(rel.parts) == 1 and top == binary_name and member.isfile()
            if not (is_binary or top in keep_dirs):
                continue
            target = (dest / rel).resolve()
            if root != target and root not in target.parents:
                continue
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                continue
            if member.size > _MAX_MEMBER_BYTES or total + member.size > _MAX_TOTAL_BYTES:
                raise DownloadError(f"Archive member '{member.name}' is unreasonably large; refusing to unpack it")
            total += member.size
            extracted = tf.extractfile(member)
            if extracted is None:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(extracted.read())
            if is_binary or member.mode & 0o111:
                target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            found = found or is_binary
    if not found:
        raise DownloadError(f"Archive did not contain a file named '{binary_name}'")


def _install_binary(engine: str, version: str, binary_bytes: bytes) -> Path:
    binary_name = paths.engine_binary_name(engine)
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


def _announce(progress: Callable[[str], None] | None, asset: ReleaseAsset) -> None:
    """Say what is about to be downloaded -- on a slow link that's the only sign of life for minutes."""
    if progress is None:
        return
    size = f" ({asset.size / 1_000_000:.1f} MB)" if asset.size else ""
    progress(f"Downloading {asset.name}{size} -- this can take a while on a slow connection...")


def install_xray(
    version: str | None = None,
    include_prerelease: bool = False,
    release: Release | None = None,
    progress: Callable[[str], None] | None = None,
) -> str:
    release = release or fetch_xray_release(version, include_prerelease)
    asset_name = xray_asset_name()
    asset = release.find(asset_name)
    if asset is None:
        raise DownloadError(f"Release {release.tag} has no asset named '{asset_name}'")

    _announce(progress, asset)
    data = _download(asset.download_url)
    if not _verify_digest_field(data, asset):
        _verify_xray_dgst(data, asset, release)

    binary_bytes = _extract_zip_binary(data, "xray")
    _install_binary(ENGINE_XRAY, release.tag, binary_bytes)
    use_version(ENGINE_XRAY, release.tag)
    return release.tag


def install_singbox(
    version: str | None = None,
    include_prerelease: bool = False,
    release: Release | None = None,
    progress: Callable[[str], None] | None = None,
) -> str:
    release = release or fetch_singbox_release(version, include_prerelease)
    asset_name = singbox_asset_name(release.tag)
    asset = release.find(asset_name)
    if asset is None:
        raise DownloadError(f"Release {release.tag} has no asset named '{asset_name}'")

    _announce(progress, asset)
    data = _download(asset.download_url)
    _verify_digest_field(data, asset)

    binary_bytes = _extract_tar_binary(data, "sing-box")
    _install_binary(ENGINE_SINGBOX, release.tag, binary_bytes)
    use_version(ENGINE_SINGBOX, release.tag)
    return release.tag


def _variant_marker() -> Path:
    return paths.engine_dir(ENGINE_AETHER) / "variant.txt"


def stored_aether_variant() -> str:
    """The Aether build flavour (musl/gnu) installed last, so `core update` keeps it."""
    marker = _variant_marker()
    if marker.exists():
        value = marker.read_text(encoding="utf-8").strip()
        if value:
            return value
    return DEFAULT_AETHER_VARIANT


def install_aether(
    version: str | None = None,
    include_prerelease: bool = False,
    release: Release | None = None,
    progress: Callable[[str], None] | None = None,
    variant: str | None = None,
) -> str:
    """Download, verify and unpack an Aether release: the `aether` binary and the `pt/` folder
    of helper programs it expects next to itself."""
    release = release or fetch_aether_release(version, include_prerelease)
    variant = variant or stored_aether_variant()
    asset_name = aether_asset_name(variant=variant)
    asset = release.find(asset_name)
    if asset is None:
        raise DownloadError(f"Release {release.tag} has no asset named '{asset_name}'")

    _announce(progress, asset)
    data = _download(asset.download_url)
    if not _verify_digest_field(data, asset) and not _verify_sha256_sidecar(data, asset, release):
        # Every Aether release carries one or the other. Unpacking and running a binary nobody
        # vouched for is the one thing an installer must not do quietly.
        raise ChecksumError(f"Release {release.tag} publishes no checksum for {asset.name}; refusing to install it")

    version_dir = paths.engine_dir(ENGINE_AETHER) / release.tag
    _extract_tar_tree(data, "aether", version_dir)
    _variant_marker().write_text(variant, encoding="utf-8")
    use_version(ENGINE_AETHER, release.tag)
    return release.tag


def fetch_release_for(engine: str, version: str | None = None, include_prerelease: bool = False) -> Release:
    """Release info for an engine, without downloading anything."""
    if engine == ENGINE_XRAY:
        return fetch_xray_release(version, include_prerelease)
    if engine == ENGINE_AETHER:
        return fetch_aether_release(version, include_prerelease)
    return fetch_singbox_release(version, include_prerelease)


def install_engine(
    engine: str,
    release: Release,
    progress: Callable[[str], None] | None = None,
    variant: str | None = None,
) -> str:
    """Install the given (already fetched) release of an engine. `variant` only matters
    for Aether (its musl or glibc build)."""
    if engine == ENGINE_XRAY:
        return install_xray(release=release, progress=progress)
    if engine == ENGINE_AETHER:
        return install_aether(release=release, progress=progress, variant=variant)
    return install_singbox(release=release, progress=progress)
