"""Integration tests: the real Xray binary checks configs v2rm generates and runs real chains.

Nothing leaves the machine. Most tests only run `xray run -test -c FILE` (the same call
`v2rm connect` makes before starting a raw/MASQUE profile); the chain tests also start real Xray
programs on loopback. They are skipped unless you opt in:

    V2RM_INTEGRATION=1 V2RM_XRAY=/path/to/xray pytest tests/integration

`V2RM_XRAY` defaults to `xray` on PATH. Geo data (for the geosite:/geoip: rules
in routing presets and in the serverless configs) is read from
`V2RM_GEO_ASSETS` if set -- point it at the directory `v2rm route update-data`
fills, normally ~/.cache/v2rm/assets -- otherwise from next to the binary.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest


@pytest.fixture(scope="session")
def xray_binary() -> Path:
    if os.environ.get("V2RM_INTEGRATION") != "1":
        pytest.skip("integration test: set V2RM_INTEGRATION=1 (and V2RM_XRAY=/path/to/xray) to run")
    candidate = os.environ.get("V2RM_XRAY") or shutil.which("xray")
    if not candidate:
        pytest.skip("no Xray binary: set V2RM_XRAY=/path/to/xray (or put xray on PATH)")
    path = Path(candidate)
    if not path.is_file():
        pytest.skip(f"V2RM_XRAY={candidate} is not a file")
    return path


@pytest.fixture(scope="session")
def xray_version(xray_binary: Path) -> str:
    """E.g. '26.3.27', read from `xray version`."""
    proc = subprocess.run([str(xray_binary), "version"], capture_output=True, text=True, timeout=30)
    match = re.search(r"Xray\s+v?(\d+(?:\.\d+)+)", (proc.stdout or "") + (proc.stderr or ""))
    if not match:
        pytest.skip(f"couldn't read Xray's version from `xray version`: {proc.stdout!r}")
    return match.group(1)


@pytest.fixture(scope="session")
def assets_dir(xray_binary: Path) -> Path:
    return Path(os.environ.get("V2RM_GEO_ASSETS") or xray_binary.parent)


# ---- real programs on loopback ----------------------------------------------------------------------------


class Hello(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = b"hello from the target"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def target():
    """A tiny HTTP server on loopback; yields its port."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), Hello)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1]
    server.shutdown()


@pytest.fixture
def run_xray(xray_binary, assets_dir, tmp_path):
    """start(name, config, port): run the real Xray with `config`, wait until `port` listens."""
    started: list[subprocess.Popen] = []

    def start(name: str, config: dict, port: int) -> None:
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        env = dict(os.environ, XRAY_LOCATION_ASSET=str(assets_dir))
        proc = subprocess.Popen(
            [str(xray_binary), "run", "-c", str(path)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT
        )
        started.append(proc)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                pytest.fail(f"xray ({name}) exited with code {proc.returncode}")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                    return
            except OSError:
                time.sleep(0.1)
        pytest.fail(f"xray ({name}) never listened on {port}")

    yield start
    for proc in started:
        proc.terminate()
    for proc in started:
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
