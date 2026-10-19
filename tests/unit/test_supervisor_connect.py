"""connect()/run_temporary()/status() with the engine stubbed out: ordering
(validate before disconnecting), what gets written, what gets probed."""

from __future__ import annotations

import contextlib
import json
import os
import socket
from pathlib import Path

import pytest

from tests.helpers import serverless_profiles
from v2rm.errors import (
    ConfigTestError,
    ConnectFailedError,
    CoreTooOldError,
    EngineNotInstalledError,
    UnsupportedProtocolError,
)
from v2rm.models.auth import ProxyAuth
from v2rm.models.enums import EngineKind, Protocol
from v2rm.models.profile import Profile
from v2rm.process import supervisor
from v2rm.routing.presets import GLOBAL
from v2rm.store import paths

BINARY = Path("/opt/v2rm/xray")


def trojan() -> Profile:
    return Profile(name="t", protocol=Protocol.TROJAN, server="t.example.com", port=443, password="pw")


def always_open(port, host="127.0.0.1", timeout=0.3):
    return True


class FakeProc:
    pid = 31337

    def __init__(self, exit_code=None):
        self.exit_code = exit_code
        self.returncode = exit_code
        self.terminated = False

    def poll(self):
        return self.exit_code

    def terminate(self):
        self.terminated = True
        self.exit_code = 0

    def wait(self, timeout=None):
        return self.exit_code

    def kill(self):
        self.exit_code = -9


@pytest.fixture
def installed_core(monkeypatch):
    """Pretend this Xray version is installed (tests may change it)."""
    state = {"version": "v26.6.27"}
    monkeypatch.setattr("v2rm.coredl.install.current_version", lambda engine: state["version"])
    return state


@pytest.fixture
def preflight_calls(monkeypatch):
    calls: list[tuple] = []
    monkeypatch.setattr(supervisor, "run_config_test", lambda *args: calls.append(args))
    return calls


@pytest.fixture
def engine_installed(monkeypatch, tmp_path):
    binary = tmp_path / "xray"
    binary.write_text("")
    monkeypatch.setattr(supervisor, "_binary_path", lambda engine: binary)
    return binary


# ---- status(): is the proxy really accepting connections? ----------------------------------


@contextlib.contextmanager
def listening_socket():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(5)
    try:
        yield server.getsockname()[1]
    finally:
        server.close()


def write_connection(meta: dict) -> None:
    paths.run_dir().mkdir(parents=True, exist_ok=True)
    paths.pid_file().write_text(str(os.getpid()))  # a live pid: this test process
    paths.engine_meta_file().write_text(json.dumps(meta))


def test_status_reports_whether_the_proxy_is_really_listening():
    with listening_socket() as port:
        write_connection({"socks_port": port, "listen_address": "127.0.0.1"})
        assert supervisor.status()["listening"] is True
    write_connection({"socks_port": port, "listen_address": "127.0.0.1"})  # the socket is closed now
    assert supervisor.status()["listening"] is False


def test_status_probes_loopback_when_the_proxy_listens_on_a_wildcard():
    with listening_socket() as port:
        write_connection({"socks_port": port, "listen_address": "0.0.0.0"})
        assert supervisor.status()["listening"] is True


def test_status_probes_the_recorded_address_not_loopback(monkeypatch):
    probed: list[str] = []
    monkeypatch.setattr(
        supervisor, "_port_open", lambda port, host="127.0.0.1", timeout=0.3: probed.append(host) or True
    )
    write_connection({"socks_port": 10808, "listen_address": "172.17.0.1"})
    assert supervisor.status()["listening"] is True
    assert probed == ["172.17.0.1"]


# ---- _prepare_config: generate + validate without starting anything --------------------------


def prepare(profile, engine, tmp_path, listen="127.0.0.1", auth=None):
    config_path = tmp_path / "config.json"
    notes = supervisor._prepare_config(profile, engine, GLOBAL, 10808, 10809, listen, auth, config_path, BINARY)
    return notes, config_path


def test_a_raw_profile_is_written_with_rewritten_inbounds_and_then_tested(tmp_path, installed_core, preflight_calls):
    _, config_path = prepare(serverless_profiles()[0], EngineKind.XRAY, tmp_path, listen="172.18.0.1")
    config = json.loads(config_path.read_text(encoding="utf-8"))
    assert [(i["protocol"], i["listen"], i["port"]) for i in config["inbounds"]] == [
        ("mixed", "172.18.0.1", 10808),
        ("http", "172.18.0.1", 10809),
    ]
    assert preflight_calls == [(BINARY, config_path, paths.geo_assets_dir())]


def test_an_ordinary_profile_is_not_tested_with_xray_first(tmp_path, installed_core, preflight_calls):
    _, config_path = prepare(trojan(), EngineKind.XRAY, tmp_path)
    assert config_path.exists()
    assert preflight_calls == []


def test_singbox_profiles_are_never_preflighted(tmp_path, installed_core, preflight_calls):
    hysteria2 = Profile(name="h", protocol=Protocol.HYSTERIA2, server="h.example.com", port=443, password="pw")
    _, config_path = prepare(hysteria2, EngineKind.SINGBOX, tmp_path)
    assert json.loads(config_path.read_text())["outbounds"][0]["type"] == "hysteria2"
    assert preflight_calls == []


def test_a_too_old_core_stops_before_anything_is_written(tmp_path, installed_core, preflight_calls):
    installed_core["version"] = "v26.3.27"
    with pytest.raises(CoreTooOldError, match="26.6.27"):
        _, config_path = prepare(serverless_profiles()[0], EngineKind.XRAY, tmp_path)
    assert not (tmp_path / "config.json").exists()
    assert preflight_calls == []


def test_a_config_xray_rejects_raises_config_test_error(tmp_path, installed_core, monkeypatch):
    def reject(*args):
        raise ConfigTestError("Xray rejected the generated config:\nunknown config id: masque")

    monkeypatch.setattr(supervisor, "run_config_test", reject)
    with pytest.raises(ConfigTestError, match="unknown config id"):
        prepare(serverless_profiles()[0], EngineKind.XRAY, tmp_path)


def test_a_profile_the_engine_cannot_run_fails_before_the_preflight(tmp_path, installed_core, preflight_calls):
    with pytest.raises(UnsupportedProtocolError):
        prepare(serverless_profiles()[0], EngineKind.SINGBOX, tmp_path)
    assert preflight_calls == []


def test_generator_notes_are_returned(tmp_path, installed_core, preflight_calls):
    profile = Profile(
        name="with-tun",
        protocol=Protocol.RAW_XRAY,
        raw_config={"inbounds": [{"tag": "t", "protocol": "tun"}], "outbounds": []},
    )
    notes, _ = prepare(profile, EngineKind.XRAY, tmp_path)
    assert len(notes) == 1 and "tun 't'" in notes[0]


# ---- connect(): the old connection survives a profile that can't run ---------------------------


def test_connect_validates_before_it_touches_the_existing_connection(monkeypatch, engine_installed, installed_core):
    disconnected: list[bool] = []
    monkeypatch.setattr(supervisor, "is_connected", lambda: (True, 4242))
    monkeypatch.setattr(supervisor, "disconnect", lambda: disconnected.append(True))

    def reject(*args):
        raise ConfigTestError("Xray rejected the generated config:\nboom")

    monkeypatch.setattr(supervisor, "run_config_test", reject)
    paths.run_dir().mkdir(parents=True, exist_ok=True)
    paths.runtime_config_file().write_text('{"still": "the old connection"}')

    with pytest.raises(ConfigTestError, match="boom"):
        supervisor.connect(serverless_profiles()[0], EngineKind.XRAY, GLOBAL, 10808, 10809)

    assert disconnected == []  # the user is still connected to what they had
    assert json.loads(paths.runtime_config_file().read_text()) == {"still": "the old connection"}
    assert not (paths.run_dir() / "config.next.json").exists()


def test_connect_refuses_a_too_old_core_without_disconnecting(monkeypatch, engine_installed, installed_core):
    installed_core["version"] = "v26.3.27"
    monkeypatch.setattr(supervisor, "is_connected", lambda: (True, 4242))
    monkeypatch.setattr(supervisor, "disconnect", lambda: pytest.fail("must not disconnect"))
    with pytest.raises(CoreTooOldError):
        supervisor.connect(serverless_profiles()[0], EngineKind.XRAY, GLOBAL, 10808, 10809)


def test_connect_without_the_engine_installed_says_how_to_install_it(monkeypatch):
    def missing(engine):
        raise EngineNotInstalledError("xray is not installed. Run `v2rm core install xray` first.")

    monkeypatch.setattr(supervisor, "_binary_path", missing)
    with pytest.raises(EngineNotInstalledError, match="core install xray"):
        supervisor.connect(trojan(), EngineKind.XRAY, GLOBAL, 10808, 10809)


def test_connect_success_validates_then_disconnects_then_starts(monkeypatch, engine_installed, installed_core):
    order: list[str] = []
    probed: list[str] = []
    started: dict = {}

    def fake_popen(args, **kwargs):
        order.append("start")
        started["args"] = args
        started["env"] = kwargs["env"]
        return FakeProc()

    monkeypatch.setattr(supervisor, "run_config_test", lambda *args: order.append("preflight"))
    monkeypatch.setattr(supervisor, "is_connected", lambda: (True, 4242))
    monkeypatch.setattr(supervisor, "disconnect", lambda: order.append("disconnect"))
    monkeypatch.setattr(supervisor.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(
        supervisor, "_port_open", lambda port, host="127.0.0.1", timeout=0.3: probed.append(host) or True
    )

    notes = supervisor.connect(
        serverless_profiles()[0], EngineKind.XRAY, GLOBAL, 10808, 10809,
        listen_address="172.18.0.1", auth=ProxyAuth("demo-user", "demo-pass"),
    )

    assert order == ["preflight", "disconnect", "start"]
    assert notes == []
    assert probed == ["172.18.0.1"]  # the address it's really bound to, not loopback
    assert started["args"][1:3] == ["run", "-c"]
    assert started["args"][3] == str(paths.runtime_config_file())  # config.next.json was moved into place
    assert started["env"]["XRAY_LOCATION_ASSET"] == str(paths.geo_assets_dir())
    assert not (paths.run_dir() / "config.next.json").exists()

    config = json.loads(paths.runtime_config_file().read_text(encoding="utf-8"))
    assert config["inbounds"][0]["listen"] == "172.18.0.1"
    assert config["inbounds"][0]["settings"]["accounts"] == [{"user": "demo-user", "pass": "demo-pass"}]

    assert paths.pid_file().read_text() == "31337"
    meta_text = paths.engine_meta_file().read_text()
    meta = json.loads(meta_text)
    assert meta["engine"] == "xray"
    assert meta["profile_kind"] == "raw"
    assert meta["listen_address"] == "172.18.0.1"
    assert meta["authenticated"] is True
    assert meta["socks_port"] == 10808 and meta["http_port"] == 10809
    assert "demo-user" not in meta_text and "demo-pass" not in meta_text  # never stored in the status file


def test_connect_does_not_disconnect_when_nothing_is_connected(monkeypatch, engine_installed, installed_core):
    monkeypatch.setattr(supervisor, "run_config_test", lambda *args: None)
    monkeypatch.setattr(supervisor, "is_connected", lambda: (False, None))
    monkeypatch.setattr(supervisor, "disconnect", lambda: pytest.fail("nothing to disconnect"))
    monkeypatch.setattr(supervisor.subprocess, "Popen", lambda args, **kw: FakeProc())
    monkeypatch.setattr(supervisor, "_port_open", always_open)
    assert supervisor.connect(trojan(), EngineKind.XRAY, GLOBAL, 10808, 10809) == []


def test_connect_reports_an_engine_that_exits_immediately_and_cleans_up(monkeypatch, engine_installed, installed_core):
    monkeypatch.setattr(supervisor, "is_connected", lambda: (False, None))
    monkeypatch.setattr(supervisor.subprocess, "Popen", lambda args, **kw: FakeProc(exit_code=1))
    monkeypatch.setattr(supervisor, "_port_open", lambda port, host="127.0.0.1", timeout=0.3: False)
    with pytest.raises(ConnectFailedError, match="exited immediately"):
        supervisor.connect(trojan(), EngineKind.XRAY, GLOBAL, 10808, 10809)
    assert not paths.pid_file().exists()
    assert not paths.engine_meta_file().exists()


# ---- run_temporary(): throwaway instance for tests ----------------------------------------------


def test_run_temporary_always_binds_loopback_and_applies_auth(monkeypatch, engine_installed, installed_core):
    captured: dict = {}
    proc = FakeProc()

    def fake_popen(args, **kwargs):
        captured["config"] = json.loads(Path(args[-1]).read_text(encoding="utf-8"))
        captured["env"] = kwargs["env"]
        return proc

    monkeypatch.setattr(supervisor, "run_config_test", lambda *args: None)
    monkeypatch.setattr(supervisor.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(supervisor, "_port_open", always_open)

    with supervisor.run_temporary(
        serverless_profiles()[0], EngineKind.XRAY, GLOBAL, 20808, 20809, auth=ProxyAuth("u", "p")
    ):
        pass

    assert [i["listen"] for i in captured["config"]["inbounds"]] == ["127.0.0.1", "127.0.0.1"]
    assert captured["config"]["inbounds"][0]["settings"]["accounts"] == [{"user": "u", "pass": "p"}]
    assert captured["env"]["XRAY_LOCATION_ASSET"] == str(paths.geo_assets_dir())
    assert proc.terminated  # the throwaway engine is always stopped
    assert not paths.pid_file().exists()  # ...and never registers as *the* connection


def test_run_temporary_collects_generator_notes(monkeypatch, engine_installed, installed_core):
    monkeypatch.setattr(supervisor, "run_config_test", lambda *args: None)
    monkeypatch.setattr(supervisor.subprocess, "Popen", lambda args, **kw: FakeProc())
    monkeypatch.setattr(supervisor, "_port_open", always_open)
    profile = Profile(
        name="with-tun",
        protocol=Protocol.RAW_XRAY,
        raw_config={"inbounds": [{"tag": "t", "protocol": "tun"}], "outbounds": []},
    )
    notes: list[str] = []
    with supervisor.run_temporary(profile, EngineKind.XRAY, GLOBAL, 20808, 20809, notes=notes):
        pass
    assert len(notes) == 1 and "tun 't'" in notes[0]
