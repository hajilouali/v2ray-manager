from __future__ import annotations

import platform
from dataclasses import dataclass, field
from typing import Any

import requests

from v2rm.constants import DEFAULT_USER_AGENT, GITHUB_API, SINGBOX_REPO, XRAY_REPO
from v2rm.errors import DownloadError

# CPU architecture (platform.machine(), lowercased) -> the suffix each
# project uses in its own release asset names.
_ARCH_MAP_XRAY = {
    "x86_64": "64",
    "amd64": "64",
    "aarch64": "arm64-v8a",
    "arm64": "arm64-v8a",
    "armv7l": "arm32-v7a",
    "armv6l": "arm32-v6",
    "i386": "32",
    "i686": "32",
}

_ARCH_MAP_SINGBOX = {
    "x86_64": "amd64",
    "amd64": "amd64",
    "aarch64": "arm64",
    "arm64": "arm64",
    "armv7l": "armv7",
    "i386": "386",
    "i686": "386",
}


@dataclass
class ReleaseAsset:
    name: str
    download_url: str
    digest: str | None = None  # "sha256:..." -- populated by GitHub for some repos/releases


@dataclass
class Release:
    tag: str
    assets: list[ReleaseAsset] = field(default_factory=list)

    def find(self, name: str) -> ReleaseAsset | None:
        for a in self.assets:
            if a.name == name:
                return a
        return None


def _get_json(url: str) -> Any:
    try:
        resp = requests.get(
            url,
            headers={"User-Agent": DEFAULT_USER_AGENT, "Accept": "application/vnd.github+json"},
            timeout=15,
        )
    except requests.RequestException as exc:
        raise DownloadError(f"Could not reach GitHub API: {exc}") from exc
    if resp.status_code == 403 and "rate limit" in resp.text.lower():
        raise DownloadError("GitHub API rate limit exceeded. Try again later.")
    if resp.status_code == 404:
        raise DownloadError(f"Not found: {url}")
    if resp.status_code != 200:
        raise DownloadError(f"GitHub API returned HTTP {resp.status_code} for {url}")
    return resp.json()


def fetch_release(repo: str, version: str | None = None) -> Release:
    path = f"tags/{version}" if version else "latest"
    data = _get_json(f"{GITHUB_API}/repos/{repo}/releases/{path}")
    assets = [
        ReleaseAsset(name=a["name"], download_url=a["browser_download_url"], digest=a.get("digest"))
        for a in data.get("assets", [])
    ]
    return Release(tag=data["tag_name"], assets=assets)


def fetch_xray_release(version: str | None = None) -> Release:
    return fetch_release(XRAY_REPO, version)


def fetch_singbox_release(version: str | None = None) -> Release:
    return fetch_release(SINGBOX_REPO, version)


def xray_asset_name(machine: str | None = None) -> str:
    machine = (machine or platform.machine()).lower()
    suffix = _ARCH_MAP_XRAY.get(machine)
    if not suffix:
        raise DownloadError(f"No known Xray-core build for CPU architecture '{machine}'")
    return f"Xray-linux-{suffix}.zip"


def singbox_asset_name(version: str, machine: str | None = None) -> str:
    machine = (machine or platform.machine()).lower()
    suffix = _ARCH_MAP_SINGBOX.get(machine)
    if not suffix:
        raise DownloadError(f"No known sing-box build for CPU architecture '{machine}'")
    version_number = version.lstrip("v")
    return f"sing-box-{version_number}-linux-{suffix}.tar.gz"
