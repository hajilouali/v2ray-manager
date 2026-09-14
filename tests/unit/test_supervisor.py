from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from v2rm.errors import NotConnectedError
from v2rm.process import supervisor
from v2rm.store import paths


def test_is_connected_false_when_no_pidfile():
    connected, pid = supervisor.is_connected()
    assert connected is False
    assert pid is None


def test_is_connected_true_for_live_pid():
    paths.run_dir().mkdir(parents=True, exist_ok=True)
    paths.pid_file().write_text(str(os.getpid()))

    connected, pid = supervisor.is_connected()
    assert connected is True
    assert pid == os.getpid()


def test_is_connected_cleans_up_stale_pidfile():
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait()
    dead_pid = proc.pid

    paths.run_dir().mkdir(parents=True, exist_ok=True)
    paths.pid_file().write_text(str(dead_pid))
    paths.engine_meta_file().write_text("{}")

    connected, pid = supervisor.is_connected()
    assert connected is False
    assert pid is None
    assert not paths.pid_file().exists()
    assert not paths.engine_meta_file().exists()


def test_disconnect_raises_when_not_connected():
    with pytest.raises(NotConnectedError):
        supervisor.disconnect()


def test_status_shape_when_not_connected():
    assert supervisor.status() == {"connected": False, "pid": None}


def test_status_includes_meta_when_connected():
    paths.run_dir().mkdir(parents=True, exist_ok=True)
    paths.pid_file().write_text(str(os.getpid()))
    paths.engine_meta_file().write_text(json.dumps({"engine": "xray", "profile_name": "Demo"}))

    info = supervisor.status()
    assert info["connected"] is True
    assert info["profile_name"] == "Demo"
    assert info["engine"] == "xray"
