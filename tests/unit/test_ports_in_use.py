"""Starting where something else already listens: caught before anything starts, and caught when
the other program's open port would otherwise make a dead engine look alive."""

from __future__ import annotations

import os
import socket
import sys
import threading

import pytest

from tests.conftest import REAL_PORTS_IN_USE
from v2rm.errors import ConnectFailedError
from v2rm.models.aether import AetherSettings
from v2rm.models.enums import Protocol
from v2rm.models.profile import Profile
from v2rm.net import addresses
from v2rm.net.ports import free_port
from v2rm.process import stack, supervisor
from v2rm.routing.presets import GLOBAL
from v2rm.store import paths
from v2rm.store.profiles import ProfileStore

FAKE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fake_engines.py")


class Holder:
    """Something else listening on a port (it answers a SOCKS5 greeting, like a real proxy)."""

    def __init__(self, host="127.0.0.1"):
        self.server = socket.socket()
        self.server.bind((host, 0))
        self.server.listen(8)
        self.port = self.server.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            try:
                conn.settimeout(1)
                if conn.recv(3)[:1] == b"\x05":
                    conn.sendall(b"\x05\x00")
            except OSError:
                pass
            finally:
                conn.close()

    def close(self):
        self.server.close()


@pytest.fixture
def holder():
    held = Holder()
    yield held
    held.close()


# ---- the probe ----------------------------------------------------------------------------------------------


def test_a_port_something_listens_on_is_in_use(holder):
    assert REAL_PORTS_IN_USE("127.0.0.1", [holder.port]) == [holder.port]


def test_a_free_port_is_not():
    assert REAL_PORTS_IN_USE("127.0.0.1", [free_port()]) == []


def test_each_port_is_judged_on_its_own(holder):
    free = free_port()
    assert REAL_PORTS_IN_USE("127.0.0.1", [free, holder.port]) == [holder.port]


def test_probing_leaves_nothing_listening():
    port = free_port()
    REAL_PORTS_IN_USE("127.0.0.1", [port])
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", port), timeout=0.3)


def test_a_wildcard_address_is_probed_too(holder):
    # Something on 127.0.0.1:port blocks 0.0.0.0:port as well on Linux; elsewhere the answer may differ,
    # but a free port must never be reported busy.
    assert REAL_PORTS_IN_USE("0.0.0.0", [free_port()]) == []


def test_the_default_probe_is_the_real_one_outside_the_tests():
    assert REAL_PORTS_IN_USE is not addresses.ports_in_use  # the autouse fixture replaced it for the suite


# ---- refusing to start --------------------------------------------------------------------------------------


@pytest.fixture
def real_probe(monkeypatch):
    monkeypatch.setattr(addresses, "ports_in_use", REAL_PORTS_IN_USE)


def test_the_message_names_the_port_and_what_to_do(real_probe, holder):
    with pytest.raises(ConnectFailedError) as caught:
        supervisor._ensure_ports_free("127.0.0.1", [holder.port, free_port()])
    text = str(caught.value)
    assert f"Port {holder.port} on 127.0.0.1 is already in use" in text
    assert "ss -ltnp" in text and "v2rm port set" in text


def test_free_ports_pass(real_probe):
    supervisor._ensure_ports_free("127.0.0.1", [free_port(), free_port()])


def add_warp(**env) -> Profile:
    return ProfileStore().add(Profile(name="warp", protocol=Protocol.AETHER, aether=AetherSettings(env=env)))


@pytest.fixture
def fake_aether(monkeypatch, tmp_path):
    monkeypatch.setattr(supervisor, "_binary_path", lambda engine: tmp_path / "fake")
    monkeypatch.setattr(stack, "stage_command", lambda stage, binary, config: [sys.executable, FAKE, "aether"])
    yield
    try:
        supervisor.disconnect()
    except Exception:  # noqa: BLE001
        pass


def test_connect_refuses_to_start_on_a_busy_port_and_starts_nothing(real_probe, holder, fake_aether, monkeypatch):
    spawned: list = []
    monkeypatch.setattr(stack, "spawn", lambda *a, **k: spawned.append(a) or None)
    with pytest.raises(ConnectFailedError, match="already in use"):
        supervisor.connect_stack(add_warp(), None, GLOBAL, holder.port, free_port())
    assert spawned == []
    assert not (paths.run_dir() / "next").exists()  # the staged configs are cleaned up too


def test_another_programs_open_port_does_not_make_a_dead_aether_look_up(holder, fake_aether):
    """The case found on a real server: the port check is skipped (a race: it was free a moment
    ago), another program answers a SOCKS5 greeting there, and Aether -- which cannot bind -- exits.
    The proxy must be reported as failed, not as connected."""
    with pytest.raises(ConnectFailedError, match="exited"):
        supervisor.connect_stack(add_warp(), None, GLOBAL, holder.port, free_port())
    assert supervisor.status() == {"connected": False, "pid": None}


def test_a_program_that_dies_right_after_it_opens_its_port_is_not_connected(fake_aether):
    with pytest.raises(ConnectFailedError, match="exited"):
        supervisor.connect_stack(add_warp(AETHER_FAKE_BEHAVIOUR="die-after-ready"), None, GLOBAL, free_port(), free_port())
    assert supervisor.status() == {"connected": False, "pid": None}
