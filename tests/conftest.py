from __future__ import annotations

import pytest

# Addresses the fake host "has" for the listen-address checks. Tests may
# add to or remove from it (`host_addresses.discard("172.17.0.1")`).
HOST_ADDRESSES = {"127.0.0.1", "172.17.0.1", "192.168.1.5"}


@pytest.fixture(autouse=True)
def _isolated_v2rm_dirs(tmp_path, monkeypatch):
    """Every test gets its own throwaway XDG-style tree instead of touching the
    real ~/.config/v2rm on whatever machine runs the suite."""
    monkeypatch.setenv("V2RM_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("V2RM_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("V2RM_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("V2RM_CACHE_HOME", str(tmp_path / "cache"))
    # rich sizes tables to the terminal; pin it wide so output assertions
    # don't depend on whatever width the test runner happens to have.
    monkeypatch.setenv("COLUMNS", "200")
    yield


@pytest.fixture(autouse=True)
def host_addresses(monkeypatch):
    """Which addresses "exist" on this host for `--listen` checks, instead of
    probing the real machine (a Docker bridge IP exists on one developer's
    laptop and not on CI). The pure bind-probe function itself is tested
    directly in test_net_addresses.py."""
    present = set(HOST_ADDRESSES)
    monkeypatch.setattr("v2rm.net.addresses.local_address_exists", lambda address: address in present)
    monkeypatch.setattr("v2rm.net.addresses.local_addresses", lambda *args, **kwargs: sorted(present))
    return present
