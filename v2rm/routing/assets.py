from __future__ import annotations

import requests

from v2rm.constants import DEFAULT_USER_AGENT, XRAY_GEOIP_DAT_URL, XRAY_GEOSITE_DAT_URL
from v2rm.errors import DownloadError
from v2rm.store import paths


def _download(url: str) -> bytes:
    try:
        resp = requests.get(url, headers={"User-Agent": DEFAULT_USER_AGENT}, timeout=60)
    except requests.RequestException as exc:
        raise DownloadError(f"Download failed: {exc}") from exc
    if resp.status_code != 200:
        raise DownloadError(f"Download failed: HTTP {resp.status_code} for {url}")
    return resp.content


def update_xray_geodata(force: bool = False) -> bool:
    """Download geoip.dat/geosite.dat (what Xray-core's geoip:/geosite:
    routing rules resolve against, loaded via XRAY_LOCATION_ASSET) into the
    assets cache. sing-box needs no equivalent step here -- it fetches its
    per-tag .srs rule-sets itself at startup via route.rule_set[].url.
    Returns True if anything was (re)written."""
    assets_dir = paths.geo_assets_dir()
    assets_dir.mkdir(parents=True, exist_ok=True)

    geoip_path = assets_dir / "geoip.dat"
    geosite_path = assets_dir / "geosite.dat"

    changed = False
    if force or not geoip_path.exists():
        geoip_path.write_bytes(_download(XRAY_GEOIP_DAT_URL))
        changed = True
    if force or not geosite_path.exists():
        geosite_path.write_bytes(_download(XRAY_GEOSITE_DAT_URL))
        changed = True
    return changed
