from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolated_v2rm_dirs(tmp_path, monkeypatch):
    """Every test gets its own throwaway XDG-style tree instead of touching the
    real ~/.config/v2rm on whatever machine runs the suite."""
    monkeypatch.setenv("V2RM_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("V2RM_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("V2RM_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("V2RM_CACHE_HOME", str(tmp_path / "cache"))
    yield
