"""Really starting a stack: processes, readiness, state files, teardown. The engines are small
Python stand-ins (tests/fake_engines.py) that listen like the real programs and log like Aether."""

from __future__ import annotations

import contextlib
import json
import os
import socket
import stat
import sys
import threading
import time
from pathlib import Path

import pytest

from v2rm.errors import (
    ConfigTestError,
    ConnectFailedError,
    EngineNotInstalledError,
    NotConnectedError,
    ProfileNotFoundError,
)
from v2rm.models.aether import AetherSettings
from v2rm.models.auth import ProxyAuth
from v2rm.models.chain import HOP_PROFILE, ChainHop
from v2rm.models.enums import EngineKind, Protocol
from v2rm.models.profile import Profile
from v2rm.net.ports import free_port
from v2rm.process import stack, supervisor
from v2rm.routing.presets import GLOBAL
from v2rm.store import paths
from v2rm.store.profiles import ProfileStore

FAKE = Path(__file__).resolve().parent.parent / "fake_engines.py"
AETHER = EngineKind.AETHER


@pytest.fixture(autouse=True)
def fake_programs(monkeypatch, tmp_path):
    """Every program of a stack is a stand-in, and whatever a test leaves running is stopped."""
    monkeypatch.setenv("FAKE_ENGINE_EVENTS", str(tmp_path / "events.txt"))
    monkeypatch.setattr(supervisor, "_binary_path", lambda engine: tmp_path / f"fake-{engine.value}")
    monkeypatch.setattr(supervisor, "run_config_test", lambda *args, **kwargs: None)
    monkeypatch.setattr(stack, "CONNECT_POLL_TIMEOUT", 15.0)

    def command(stage, binary, config_path):
        if stage.engine == AETHER:
            return [sys.executable, str(FAKE), "aether"]
        return [sys.executable, str(FAKE), "engine", "run", "-c", str(config_path)]

    monkeypatch.setattr(stack, "stage_command", command)
    yield
    with contextlib.suppress(NotConnectedError):
        supervisor.disconnect()


def events(tmp_path) -> list[str]:
    path = tmp_path / "events.txt"
    return path.read_text(encoding="utf-8").splitlines() if path.exists() else []


def add_aether(name="warp", **settings) -> Profile:
    return ProfileStore().add(Profile(name=name, protocol=Protocol.AETHER, aether=AetherSettings(**settings)))


def add_trojan(name="trojan") -> Profile:
    return ProfileStore().add(
        Profile(name=name, protocol=Protocol.TROJAN, server=f"{name}.example.com", port=443, password="pw")
    )


def add_chain(name, *members) -> Profile:
    hops = [ChainHop(HOP_PROFILE, m.id, m.name) for m in members]
    return ProfileStore().add(Profile(name=name, protocol=Protocol.CHAIN, chain=hops))


def connect(profile, auth=None, progress=None, route=GLOBAL, listen="127.0.0.1"):
    ports = (free_port(), free_port())
    notes = supervisor.connect_stack(profile, None, route, *ports, listen_address=listen, auth=auth, progress=progress)
    return ports, notes


def alive(pid) -> bool:
    return supervisor._is_alive(pid)


def stage_pids() -> list[int]:
    return [m["pid"] for m in supervisor._stack_members()]


# ---- an Aether profile on its own --------------------------------------------------------------


def test_aether_comes_up_listening_where_the_user_asked(tmp_path, monkeypatch):
    record = tmp_path / "env.json"
    # What the user's shell holds must not leak into the profile.
    monkeypatch.setenv("AETHER_SOCKS", "0.0.0.0:1")
    monkeypatch.setenv("RUST_LOG", "trace")
    warp = add_aether(env={"AETHER_FAKE_RECORD": str(record)}, transport="h2", noize="gfw")

    (socks, http), notes = connect(warp)

    assert stack.socks5_ready("127.0.0.1", socks)
    seen = json.loads(record.read_text(encoding="utf-8").splitlines()[0])
    assert seen["AETHER_SOCKS"] == f"127.0.0.1:{socks}"
    assert seen["AETHER_HTTP_PROXY"] == f"127.0.0.1:{http}"
    assert seen["AETHER_MASQUE_HTTP2"] == "1" and seen["AETHER_NOIZE"] == "gfw"
    assert "RUST_LOG" not in seen
    where = json.loads(record.read_text(encoding="utf-8").splitlines()[1])
    assert Path(where["cwd"]).resolve() == paths.aether_profile_dir(warp.id).resolve()
    if os.name == "posix":  # Windows reports its NUL device as a terminal; Aether runs on Linux
        assert where["stdin_is_tty"] is False  # Aether would ask questions if it saw a terminal
    assert any("registers a free anonymous" in n for n in notes)


def test_status_describes_the_stack_and_disconnect_stops_it():
    (socks, _), _ = connect(add_aether())
    info = supervisor.status()

    assert info["connected"] and info["state"] == "running" and info["engine"] == "aether"
    assert info["listening"] is True and info["profile_kind"] == "aether"
    (member,) = info["stack"]
    assert member["alive"] and member["user_facing"] and member["engine"] == "aether"
    pid = member["pid"]

    supervisor.disconnect()
    assert not alive(pid)
    assert not paths.pid_file().exists() and not paths.engine_meta_file().exists()
    assert not stack.socks5_ready("127.0.0.1", socks)


def test_the_aether_log_is_the_engine_log_of_the_connection():
    connect(add_aether())
    assert "masque tunnel validated" in paths.engine_log_file().read_text(encoding="utf-8")


def test_progress_lines_are_shown_as_aether_works():
    seen: list[str] = []
    connect(add_aether(name="my warp", env={"AETHER_FAKE_BEHAVIOUR": "slow:1"}), progress=seen.append)

    assert seen[0] == "Starting my warp (aether)..."
    assert any("[*] hunting for a working MASQUE gateway" in line for line in seen)
    assert any("[+] using cloudflare edge 162.159.198.1:443" in line for line in seen)
    assert all(line.startswith(("Starting", "my warp (aether): ")) for line in seen)
    assert len(seen) == len(set(seen))  # each line once


def test_a_failing_aether_reports_why_and_leaves_nothing_behind():
    broken = add_aether(env={"AETHER_FAKE_BEHAVIOUR": "exit"})
    with pytest.raises(ConnectFailedError, match="exited") as caught:
        connect(broken)
    assert "fake failure" in str(caught.value)
    assert not paths.pid_file().exists() and not paths.engine_meta_file().exists()


def test_an_aether_that_never_comes_up_times_out_with_its_log(monkeypatch):
    monkeypatch.setattr(stack, "aether_start_timeout", lambda: 1.5)
    stuck = add_aether(env={"AETHER_FAKE_BEHAVIOUR": "never"})
    with pytest.raises(ConnectFailedError, match="was not ready") as caught:
        connect(stuck)
    assert "rescanning shortly" in str(caught.value)
    assert not paths.pid_file().exists()


# ---- chains ----------------------------------------------------------------------------------------


def test_a_chain_starts_its_hops_in_order_and_the_last_one_is_the_users(tmp_path):
    warp, server = add_aether(), add_trojan()
    (socks, http), _ = connect(add_chain("c", warp, server))

    assert [line.split()[0] for line in events(tmp_path)] == ["aether", "engine"]
    assert stack.socks5_ready("127.0.0.1", socks)  # the engine stand-in answers on the user's port

    info = supervisor.status()
    assert [m["engine"] for m in info["stack"]] == ["aether", "xray"]
    assert [m["user_facing"] for m in info["stack"]] == [False, True]
    assert info["hops"] == [warp.name, server.name]
    assert info["aether_ids"] == [warp.id]
    assert info["pid"] == info["stack"][1]["pid"]  # the pid file points at what the user talks to

    config = json.loads((paths.run_dir() / "stage-1.json").read_text(encoding="utf-8"))
    assert config["inbounds"][0]["port"] == socks
    dialer = next(o for o in config["outbounds"] if o["tag"] == "v2rm-upstream")
    assert dialer["settings"]["servers"][0]["port"] == info["stack"][0]["socks_port"]
    assert paths.runtime_config_file().read_text(encoding="utf-8") == (paths.run_dir() / "stage-1.json").read_text(
        encoding="utf-8"
    )
    assert not (paths.run_dir() / "next").exists()


def test_disconnect_stops_every_hop():
    connect(add_chain("c", add_trojan("one"), add_aether(), add_trojan("two")))
    pids = stage_pids()
    assert len(pids) == 3 and all(alive(p) for p in pids)

    supervisor.disconnect()

    assert not any(alive(p) for p in pids)
    assert list(paths.run_dir().glob("stage-*.json")) == []


def test_a_login_starts_an_xray_front_after_aether(tmp_path):
    (socks, _), notes = connect(add_aether(), auth=ProxyAuth("user", "pw"))

    assert [line.split()[0] for line in events(tmp_path)] == ["aether", "engine"]
    info = supervisor.status()
    assert [m["engine"] for m in info["stack"]] == ["aether", "xray"]
    assert info["authenticated"] is True and info["socks_port"] == socks
    assert any("front" in n for n in notes)


def test_the_config_files_are_private():
    connect(add_chain("c", add_aether(), add_trojan()))
    if os.name == "posix":
        mode = stat.S_IMODE((paths.run_dir() / "stage-1.json").stat().st_mode)
        assert mode == 0o600


def test_a_chain_with_a_missing_member_is_refused_without_touching_the_current_connection():
    (socks, _), _ = connect(add_aether("first"))
    gone, warp = add_trojan("gone"), add_aether("second")
    chain = add_chain("c", warp, gone)
    ProfileStore().remove(gone.id)

    with pytest.raises(ProfileNotFoundError):
        connect(chain)

    assert supervisor.status()["connected"] and stack.socks5_ready("127.0.0.1", socks)


def test_a_config_the_engine_rejects_leaves_the_current_connection_alone(monkeypatch):
    (socks, _), _ = connect(add_aether("first"))
    chain = add_chain("c", add_aether("second"), add_trojan())

    def reject(*args, **kwargs):
        raise ConfigTestError("bad config")

    monkeypatch.setattr(supervisor, "run_config_test", reject)
    with pytest.raises(ConfigTestError):
        connect(chain)

    assert stack.socks5_ready("127.0.0.1", socks)
    assert not (paths.run_dir() / "next").exists()


def test_connecting_another_profile_replaces_the_stack(tmp_path):
    connect(add_chain("one", add_aether("a"), add_trojan("x")))
    first = stage_pids()
    connect(add_aether("b"))
    assert not any(alive(p) for p in first)
    assert len(stage_pids()) == 1 and alive(stage_pids()[0])
    assert supervisor.status()["profile_name"] == "b"


def test_a_hop_that_fails_stops_the_hops_already_started(tmp_path):
    ok = add_aether("fine")
    broken = add_aether("broken", env={"AETHER_FAKE_BEHAVIOUR": "exit"})
    with pytest.raises(ConnectFailedError, match="broken"):
        connect(add_chain("c", ok, add_trojan(), broken))

    started = [int(line.split()[1]) for line in events(tmp_path)]
    time.sleep(0.2)
    assert not paths.pid_file().exists()
    assert started  # the first hop did start
    # Nothing is left listening on the first hop's port.
    assert not any(stack.socks5_ready("127.0.0.1", port) for port in started)


def test_a_failing_stage_is_not_mistaken_for_a_connection_in_status():
    with pytest.raises(ConnectFailedError):
        connect(add_aether(env={"AETHER_FAKE_BEHAVIOUR": "exit"}))
    assert supervisor.status() == {"connected": False, "pid": None}


# ---- when part of a stack dies -------------------------------------------------------------------


def test_status_notices_a_hop_that_died():
    connect(add_chain("c", add_aether(), add_trojan()))
    first, _ = stage_pids()
    stack._signal_group(first, 15)
    deadline = time.monotonic() + 5
    while alive(first) and time.monotonic() < deadline:
        time.sleep(0.05)

    info = supervisor.status()
    assert info["connected"] is True  # what the user talks to is still there
    assert info["degraded"] is True
    assert [m["alive"] for m in info["stack"]] == [False, True]


def test_when_the_front_dies_the_hops_behind_it_are_stopped_too():
    connect(add_chain("c", add_aether(), add_trojan()))
    first, last = stage_pids()
    stack._signal_group(last, 15)
    deadline = time.monotonic() + 5
    while alive(last) and time.monotonic() < deadline:
        time.sleep(0.05)

    connected, _ = supervisor.is_connected()
    assert connected is False
    assert not alive(first)
    assert not paths.engine_meta_file().exists()


# ---- missing programs ----------------------------------------------------------------------------


def test_a_missing_aether_says_how_to_install_it(monkeypatch, tmp_path):
    def missing(engine):
        raise EngineNotInstalledError(f"{engine.value} is not installed. Run `v2rm core install {engine.value}` first.")

    monkeypatch.setattr(supervisor, "_binary_path", missing)
    with pytest.raises(EngineNotInstalledError, match="core install aether"):
        connect(add_aether())


def test_a_missing_xray_explains_why_a_login_needs_it(monkeypatch, tmp_path):
    def only_aether(engine):
        if engine == EngineKind.XRAY:
            raise EngineNotInstalledError("xray is not installed. Run `v2rm core install xray` first.")
        return tmp_path / "fake-aether"

    monkeypatch.setattr(supervisor, "_binary_path", only_aether)
    with pytest.raises(EngineNotInstalledError, match="in front of Aether needs Xray-core"):
        connect(add_aether(), auth=ProxyAuth("u", "p"))
    connect(add_aether("plain"))  # without a login Aether needs nothing else


# ---- throwaway stacks for `test` ------------------------------------------------------------------


def test_a_temporary_stack_serves_and_then_disappears(tmp_path):
    chain = add_chain("c", add_aether(), add_trojan())
    socks, http = free_port(), free_port()
    notes: list[str] = []

    with supervisor.run_temporary_stack(chain, None, socks, http, notes=notes) as plan:
        assert stack.socks5_ready("127.0.0.1", socks)
        assert len(plan.stages) == 2
        assert not paths.pid_file().exists()  # a test never touches the live connection's state
    assert not stack.socks5_ready("127.0.0.1", socks)
    assert any("registers" in n for n in notes)


def test_a_temporary_stack_that_fails_cleans_up_what_it_started(tmp_path):
    chain = add_chain("c", add_aether(), add_aether("broken", env={"AETHER_FAKE_BEHAVIOUR": "exit"}))
    socks = free_port()
    with pytest.raises(ConnectFailedError):
        with supervisor.run_temporary_stack(chain, None, socks, free_port()):
            pass  # pragma: no cover
    first_port = int(events(tmp_path)[0].split()[1])
    assert not stack.socks5_ready("127.0.0.1", first_port)


# ---- the pieces ------------------------------------------------------------------------------------


def listener(reply: bytes | None):
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(4)

    def serve():
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            if reply is not None:
                conn.recv(3)
                conn.sendall(reply)
            threading.Timer(2, conn.close).start()

    threading.Thread(target=serve, daemon=True).start()
    return server, server.getsockname()[1]


def test_socks5_ready_wants_a_socks5_answer_not_just_an_open_port():
    good, good_port = listener(b"\x05\x00")
    mute, mute_port = listener(None)
    wrong, wrong_port = listener(b"HT")
    try:
        assert stack.socks5_ready("127.0.0.1", good_port)
        assert not stack.socks5_ready("127.0.0.1", mute_port, timeout=0.3)
        assert not stack.socks5_ready("127.0.0.1", wrong_port)
        assert not stack.socks5_ready("127.0.0.1", free_port())
    finally:
        for server in (good, mute, wrong):
            server.close()


def test_log_lines_lose_their_logger_prefix():
    assert stack.log_message("[2026-10-20T10:20:30.123Z INFO  aether] [+] using cloudflare edge 1.1.1.1:443") == (
        "[+] using cloudflare edge 1.1.1.1:443"
    )
    assert stack.log_message("[2026-10-20T10:20:30.123Z WARN  aether::quic] [-] gateway failed") == "[-] gateway failed"
    assert stack.log_message("Error: the listener cannot use that address") == "Error: the listener cannot use that address"
    assert stack.is_progress_line("[+] ok") and stack.is_progress_line("[-] bad") and stack.is_progress_line("[*] busy")
    assert not stack.is_progress_line("Aether v2.3.0") and not stack.is_progress_line("[netstack] noise")


def test_the_log_follower_returns_each_complete_line_once(tmp_path):
    path = tmp_path / "log.txt"
    follower = stack.LogFollower(path)
    assert follower.new_lines() == []
    path.write_text("one\ntw", encoding="utf-8")
    assert follower.new_lines() == ["one"]
    with path.open("a", encoding="utf-8") as fh:
        fh.write("o\nthree\n")
    assert follower.new_lines() == ["two", "three"]
    assert follower.new_lines() == []
