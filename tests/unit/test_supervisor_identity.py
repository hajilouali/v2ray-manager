"""A pid file that outlived its process (a reboot, a crash) must never make v2rm treat -- or
signal -- whatever program now has that pid."""

from __future__ import annotations

import json
import os
import sys

import pytest

from v2rm.errors import NotConnectedError
from v2rm.process import stack, supervisor
from v2rm.store import paths


def write_state(meta: dict, pid: int | None = None) -> None:
    paths.run_dir().mkdir(parents=True, exist_ok=True)
    paths.pid_file().write_text(str(pid or os.getpid()))
    paths.engine_meta_file().write_text(json.dumps(meta))


@pytest.fixture
def tokens(monkeypatch):
    """The start token each pid 'really' has right now (tests set it)."""
    current: dict[int, str] = {}
    monkeypatch.setattr(supervisor, "_start_token", lambda pid: current.get(pid))
    return current


@pytest.fixture
def signals(monkeypatch):
    """Real signals sent (signal 0 is only an "is it there?" probe and doesn't count)."""
    sent: list[tuple[int, int]] = []

    def kill(pid, sig):
        if sig != 0:
            sent.append((pid, sig))

    monkeypatch.setattr(os, "kill", kill)
    if hasattr(os, "killpg"):
        monkeypatch.setattr(os, "killpg", kill)
    return sent


def test_a_matching_token_is_the_same_process(tokens):
    tokens[os.getpid()] = "123"
    assert supervisor._same_process(os.getpid(), "123")
    assert not supervisor._same_process(os.getpid(), "999")


def test_without_a_recorded_token_or_a_way_to_read_one_nothing_is_ruled_out(tokens):
    assert supervisor._same_process(os.getpid(), None)  # nothing was recorded
    assert supervisor._same_process(os.getpid(), "123")  # the system can't say (no /proc)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads /proc")
def test_the_real_token_is_stable_for_a_process_and_differs_between_processes():
    import subprocess

    mine = supervisor._start_token(os.getpid())
    assert mine and mine == supervisor._start_token(os.getpid())
    other = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(5)"])
    try:
        assert supervisor._start_token(other.pid) != mine
    finally:
        other.kill()
        other.wait()


# ---- an ordinary connection ------------------------------------------------------------------------------------


def test_a_pid_that_now_belongs_to_another_process_is_not_a_connection(tokens):
    tokens[os.getpid()] = "after-reboot"
    write_state({"engine": "xray", "pid_start": "before-reboot"})

    assert supervisor.is_connected() == (False, None)
    assert not paths.pid_file().exists() and not paths.engine_meta_file().exists()


def test_disconnect_does_not_signal_a_process_that_only_reuses_the_pid(tokens, signals):
    tokens[os.getpid()] = "after-reboot"
    write_state({"engine": "xray", "pid_start": "before-reboot"})

    with pytest.raises(NotConnectedError):
        supervisor.disconnect()
    assert signals == []
    assert not paths.pid_file().exists()


def test_a_connection_whose_token_still_matches_is_connected(tokens):
    tokens[os.getpid()] = "same"
    write_state({"engine": "xray", "pid_start": "same", "profile_name": "P"})
    connected, pid = supervisor.is_connected()
    assert connected and pid == os.getpid()


# ---- a stack -----------------------------------------------------------------------------------------------------


def member(pid, start, facing=False, label="x"):
    return {"label": label, "engine": "xray", "pid": pid, "listen": "127.0.0.1", "socks_port": 1,
            "user_facing": facing, "start": start, "log": "/l"}


def test_status_does_not_call_a_reused_pid_alive(tokens):
    tokens[os.getpid()] = "t1"
    write_state(
        {"engine": "xray", "pid_start": "t1", "socks_port": 1, "http_port": 2,
         "stack": [member(os.getpid(), "t1", facing=True, label="front"), member(os.getpid(), "other", label="hop")]}
    )
    info = supervisor.status()
    assert [m["alive"] for m in info["stack"]] == [True, False]
    assert info["degraded"] is True


def test_disconnect_stops_only_the_members_that_are_still_ours(tokens, monkeypatch):
    tokens[os.getpid()] = "mine"
    stopped: list[list[int]] = []
    monkeypatch.setattr(stack, "stop_pids", lambda pids, grace=3.0: stopped.append(list(pids)))
    write_state(
        {"engine": "xray", "pid_start": "mine", "socks_port": 1, "http_port": 2,
         "stack": [member(os.getpid(), "reused-by-something-else", label="hop"), member(os.getpid(), "mine", facing=True)]}
    )
    supervisor.disconnect()
    assert stopped == [[os.getpid()]]  # one entry: the member that matched


def test_a_stack_none_of_whose_members_are_ours_is_not_connected(tokens, signals):
    tokens[os.getpid()] = "new"
    write_state({"engine": "xray", "pid_start": "old", "stack": [member(os.getpid(), "old", facing=True)]})
    with pytest.raises(NotConnectedError):
        supervisor.disconnect()
    assert signals == []


@pytest.fixture
def sleeper():
    import subprocess

    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    yield proc
    proc.kill()
    proc.wait()


@pytest.mark.parametrize("recorded, expected", [("mine", [[1]]), ("reused", [])])
def test_orphans_of_a_dead_front_are_stopped_only_if_they_are_ours(tokens, monkeypatch, sleeper, recorded, expected):
    stopped: list[list[int]] = []
    monkeypatch.setattr(stack, "stop_pids", lambda pids, grace=3.0: stopped.append([1] if pids == [sleeper.pid] else pids))
    tokens[sleeper.pid] = "mine"
    dead_front = os.getpid() + 1_000_000  # no such process: the program the user talked to is gone
    write_state(
        {"engine": "xray", "pid_start": "front", "stack": [member(sleeper.pid, recorded, label="hop"), member(dead_front, "front", facing=True)]},
        pid=dead_front,
    )

    assert supervisor.is_connected() == (False, None)  # finds the front dead and cleans up
    assert stopped == expected
