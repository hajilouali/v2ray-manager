from __future__ import annotations

import requests

from v2rm.routing.assets import update_xray_geodata
from v2rm.store import paths


class FakeResponse:
    def __init__(self, status_code: int = 200, content: bytes = b""):
        self.status_code = status_code
        self.content = content


def test_update_xray_geodata_downloads_both_files(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(200, b"FAKEDATA"))

    changed = update_xray_geodata()
    assert changed is True

    assets_dir = paths.geo_assets_dir()
    assert (assets_dir / "geoip.dat").read_bytes() == b"FAKEDATA"
    assert (assets_dir / "geosite.dat").read_bytes() == b"FAKEDATA"


def test_update_xray_geodata_skips_when_already_cached(monkeypatch):
    calls = []

    def fake_get(url, headers=None, timeout=None):
        calls.append(url)
        return FakeResponse(200, b"DATA")

    monkeypatch.setattr(requests, "get", fake_get)
    update_xray_geodata()
    assert len(calls) == 2

    changed = update_xray_geodata()
    assert changed is False
    assert len(calls) == 2


def test_update_xray_geodata_force_redownloads(monkeypatch):
    calls = []

    def fake_get(url, headers=None, timeout=None):
        calls.append(url)
        return FakeResponse(200, b"DATA")

    monkeypatch.setattr(requests, "get", fake_get)
    update_xray_geodata()
    update_xray_geodata(force=True)
    assert len(calls) == 4
