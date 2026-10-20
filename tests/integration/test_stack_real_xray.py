"""The whole stack with the real Xray, on loopback (see conftest.py to enable).

`v2rm connect` for a chain and for an Aether profile with a login, start to finish: the real Xray
runs the server, the chained hop and the front; a stand-in plays Aether (tests/fake_engines.py,
a working SOCKS5 relay) because the real one needs the network and a WARP registration. Real
traffic goes through the proxy v2rm serves and the test checks which hop carried it.
"""

from __future__ import annotations

import socket
import sys
import time
from pathlib import Path

import pytest
import requests

from tests.integration.support import http_proxy_get, socks_get, trojan_server
from v2rm.models.aether import AetherSettings
from v2rm.models.auth import ProxyAuth
from v2rm.models.chain import HOP_PROFILE, ChainHop
from v2rm.models.enums import EngineKind, Protocol
from v2rm.models.profile import Profile
from v2rm.net.ports import free_port
from v2rm.process import stack, supervisor
from v2rm.routing.presets import GLOBAL
from v2rm.store.profiles import ProfileStore

pytestmark = pytest.mark.integration

FAKE = Path(__file__).resolve().parent.parent / "fake_engines.py"


@pytest.fixture
def real_xray_fake_aether(monkeypatch, tmp_path, xray_binary, assets_dir):
    """Xray stages run the real binary; the Aether stage runs the SOCKS5-relaying stand-in."""
    events = tmp_path / "events.txt"
    monkeypatch.setenv("FAKE_ENGINE_EVENTS", str(events))
    monkeypatch.setenv("V2RM_GEO_ASSETS", str(assets_dir))
    monkeypatch.setattr(supervisor.paths, "geo_assets_dir", lambda: assets_dir)
    monkeypatch.setattr(
        supervisor, "_binary_path", lambda engine: xray_binary if engine != EngineKind.AETHER else tmp_path / "fake-aether"
    )

    def command(stage, binary, config_path):
        if stage.engine == EngineKind.AETHER:
            return [sys.executable, str(FAKE), "aether"]
        return [str(binary), "run", "-c", str(config_path)]

    monkeypatch.setattr(stack, "stage_command", command)
    yield events
    try:
        supervisor.disconnect()
    except Exception:  # noqa: BLE001 - nothing left to stop is fine
        pass


def relayed(events: Path) -> list[str]:
    if not events.exists():
        return []
    return [line.split(" ", 1)[1] for line in events.read_text(encoding="utf-8").splitlines() if line.startswith("relay ")]


def warp_profile(name="warp") -> Profile:
    return ProfileStore().add(
        Profile(
            name=name,
            protocol=Protocol.AETHER,
            aether=AetherSettings(env={"AETHER_FAKE_PROXY": "1"}),
        )
    )


def test_a_chain_carries_real_traffic_through_each_hop(real_xray_fake_aether, run_xray, target):
    server_port = free_port()
    run_xray("server", trojan_server(server_port), server_port)
    store = ProfileStore()
    warp = warp_profile()
    server = store.add(Profile(name="server", protocol=Protocol.TROJAN, server="127.0.0.1", port=server_port, password="pw"))
    chain = store.add(
        Profile(
            name="warp-then-server",
            protocol=Protocol.CHAIN,
            chain=[ChainHop(HOP_PROFILE, warp.id, warp.name), ChainHop(HOP_PROFILE, server.id, server.name)],
        )
    )

    socks, http = free_port(), free_port()
    notes = supervisor.connect_stack(chain, None, GLOBAL, socks, http)

    assert any("First connection of 'warp'" in n for n in notes)  # no identity yet: it would register one
    info = supervisor.status()
    assert info["connected"] and info["listening"] is True and info["hops"] == ["warp", "server"]
    assert [m["engine"] for m in info["stack"]] == ["aether", "xray"]

    # Over SOCKS and over the HTTP port.
    assert socks_get(socks, f"http://127.0.0.1:{target}/").text == "hello from the target"
    assert http_proxy_get(http, f"http://127.0.0.1:{target}/").text == "hello from the target"

    # The fake Aether relayed the connection to the *server* (the trojan hop's own connection),
    # not to the final target: the target is reached by the server on the far side.
    deadline = time.monotonic() + 5
    while f"127.0.0.1:{server_port}" not in relayed(real_xray_fake_aether) and time.monotonic() < deadline:
        time.sleep(0.1)
    assert f"127.0.0.1:{server_port}" in relayed(real_xray_fake_aether)
    assert f"127.0.0.1:{target}" not in relayed(real_xray_fake_aether)

    stage_pids = [m["pid"] for m in info["stack"]]
    supervisor.disconnect()
    assert not any(supervisor._is_alive(p) for p in stage_pids)
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", socks), timeout=0.5)


def test_an_aether_profile_with_a_login_is_served_by_the_xray_front(real_xray_fake_aether, target):
    warp = warp_profile()
    login = ProxyAuth("user", "p@ss:word")
    socks, http = free_port(), free_port()

    supervisor.connect_stack(warp, None, GLOBAL, socks, http, auth=login)

    info = supervisor.status()
    assert [m["engine"] for m in info["stack"]] == ["aether", "xray"]
    assert info["authenticated"] is True

    assert socks_get(socks, f"http://127.0.0.1:{target}/", auth=login).text == "hello from the target"
    assert http_proxy_get(http, f"http://127.0.0.1:{target}/", auth=login).text == "hello from the target"
    assert f"127.0.0.1:{target}" in relayed(real_xray_fake_aether)  # Aether carried the final request

    for call in (lambda: socks_get(socks, f"http://127.0.0.1:{target}/"), lambda: http_proxy_get(http, f"http://127.0.0.1:{target}/")):
        try:
            response = call()
        except requests.exceptions.RequestException:
            continue
        assert response.status_code == 407, response.status_code


def test_an_aether_profile_without_a_login_is_served_by_aether_itself(real_xray_fake_aether, target):
    warp = warp_profile()
    socks, http = free_port(), free_port()

    supervisor.connect_stack(warp, None, GLOBAL, socks, http)

    assert [m["engine"] for m in supervisor.status()["stack"]] == ["aether"]  # no Xray at all
    assert socks_get(socks, f"http://127.0.0.1:{target}/").text == "hello from the target"
