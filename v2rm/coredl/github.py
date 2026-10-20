from __future__ import annotations

import os
import platform
import time
from dataclasses import dataclass, field
from typing import Any

import requests

from v2rm.constants import AETHER_REPO, DEFAULT_USER_AGENT, GITHUB_API, SINGBOX_REPO, XRAY_REPO
from v2rm.engines.versioning import parse_version
from v2rm.errors import DownloadError

# How many of the newest releases to look at when pre-releases are wanted. GitHub's
# "latest" endpoint skips them, and Xray-core, for one, has published only
# pre-releases since early 2026. Release notes make each entry large, so keep it small.
PRERELEASE_WINDOW = 6

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


# Aether ships, per CPU, a glibc build (made on the newest Fedora, so it can need a newer
# glibc than Debian/Ubuntu LTS have) and a fully static musl one that runs on any Linux.
# musl is the default: "it starts" beats "it is the usual libc".
AETHER_VARIANTS = ("musl", "gnu")
DEFAULT_AETHER_VARIANT = "musl"

_AETHER_ASSETS = {
    # machine -> {variant: asset name}
    "x86_64": {"gnu": "aether-linux-x86_64.tar.gz", "musl": "aether-linux-x86_64-musl.tar.gz"},
    "aarch64": {"gnu": "aether-linux-arm64.tar.gz", "musl": "aether-linux-aarch64-musl.tar.gz"},
    "armv7": {"gnu": "aether-linux-armv7.tar.gz", "musl": "aether-linux-armv7-musl.tar.gz"},
}
_AETHER_MACHINES = {
    "x86_64": "x86_64",
    "amd64": "x86_64",
    "aarch64": "aarch64",
    "arm64": "aarch64",
    "armv7l": "armv7",
    "armv7": "armv7",
}


@dataclass
class ReleaseAsset:
    name: str
    download_url: str
    digest: str | None = None  # "sha256:..." -- populated by GitHub for some repos/releases
    size: int | None = None  # bytes, as GitHub reports them


@dataclass
class Release:
    tag: str
    assets: list[ReleaseAsset] = field(default_factory=list)
    prerelease: bool = False

    def find(self, name: str) -> ReleaseAsset | None:
        for a in self.assets:
            if a.name == name:
                return a
        return None


def _api_headers() -> dict[str, str]:
    """Anonymous GitHub API use is limited to 60 requests an hour *per IP address*, which a
    shared server or NAT can use up without v2rm doing much; a token (the one `gh` and CI
    already use) gets 5000. It is only ever sent to the API, never with asset downloads."""
    headers = {"User-Agent": DEFAULT_USER_AGENT, "Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token.strip()}"
    return headers


def _rate_limit_message(resp: Any) -> str:
    message = "GitHub API rate limit exceeded (60 requests an hour per IP address without a token)."
    reset = (getattr(resp, "headers", None) or {}).get("X-RateLimit-Reset")
    try:
        minutes = max(0, int(reset) - int(time.time())) // 60 + 1
        message += f" It resets in about {minutes} min."
    except (TypeError, ValueError):
        pass
    return message + " Try again then, or set GITHUB_TOKEN to use your own quota."


def _get_json(url: str) -> Any:
    try:
        resp = requests.get(url, headers=_api_headers(), timeout=15)
    except requests.RequestException as exc:
        raise DownloadError(f"Could not reach GitHub API: {exc}") from exc
    if resp.status_code == 403 and "rate limit" in resp.text.lower():
        raise DownloadError(_rate_limit_message(resp))
    if resp.status_code == 404:
        raise DownloadError(f"Not found: {url}")
    if resp.status_code != 200:
        raise DownloadError(f"GitHub API returned HTTP {resp.status_code} for {url}")
    return resp.json()


def _release_from(data: dict[str, Any]) -> Release:
    assets = [
        ReleaseAsset(
            name=a["name"],
            download_url=a["browser_download_url"],
            digest=a.get("digest"),
            size=a.get("size") if isinstance(a.get("size"), int) else None,
        )
        for a in data.get("assets", [])
    ]
    return Release(tag=data["tag_name"], assets=assets, prerelease=bool(data.get("prerelease")))


def newest_release(items: list[dict[str, Any]]) -> dict[str, Any]:
    """The release with the highest version number among `items` (drafts
    skipped). A stable release outranks a pre-release of the same number."""
    candidates = [r for r in items if isinstance(r, dict) and not r.get("draft") and r.get("tag_name")]
    if not candidates:
        raise DownloadError("GitHub lists no releases for this project")
    return max(candidates, key=lambda r: (parse_version(str(r["tag_name"])), not r.get("prerelease")))


def fetch_release(repo: str, version: str | None = None, include_prerelease: bool = False) -> Release:
    """One release: a specific tag (pre-releases included), the newest release
    of any kind (`include_prerelease`), or -- the default -- GitHub's "latest",
    which never returns a pre-release."""
    if version:
        data = _get_json(f"{GITHUB_API}/repos/{repo}/releases/tags/{version}")
    elif include_prerelease:
        data = newest_release(_get_json(f"{GITHUB_API}/repos/{repo}/releases?per_page={PRERELEASE_WINDOW}"))
    else:
        data = _get_json(f"{GITHUB_API}/repos/{repo}/releases/latest")
    return _release_from(data)


def fetch_xray_release(version: str | None = None, include_prerelease: bool = False) -> Release:
    return fetch_release(XRAY_REPO, version, include_prerelease)


def fetch_singbox_release(version: str | None = None, include_prerelease: bool = False) -> Release:
    return fetch_release(SINGBOX_REPO, version, include_prerelease)


def fetch_aether_release(version: str | None = None, include_prerelease: bool = False) -> Release:
    return fetch_release(AETHER_REPO, version, include_prerelease)


def aether_asset_name(machine: str | None = None, variant: str | None = None) -> str:
    machine = (machine or platform.machine()).lower()
    variant = (variant or DEFAULT_AETHER_VARIANT).lower()
    if variant not in AETHER_VARIANTS:
        raise DownloadError(f"Unknown Aether build variant '{variant}'. Choose one of: {', '.join(AETHER_VARIANTS)}")
    arch = _AETHER_MACHINES.get(machine)
    if not arch:
        raise DownloadError(f"No known Aether build for CPU architecture '{machine}'")
    return _AETHER_ASSETS[arch][variant]


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
