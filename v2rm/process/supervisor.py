from __future__ import annotations

import contextlib
import json
import os
import signal
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from v2rm.constants import CONNECT_POLL_INTERVAL, CONNECT_POLL_TIMEOUT, DISCONNECT_GRACE_SECONDS
from v2rm.errors import ConnectFailedError, EngineNotInstalledError, NotConnectedError
from v2rm.models.enums import EngineKind
from v2rm.models.profile import Profile
from v2rm.routing.model import RoutePlan
from v2rm.store import paths


def _binary_path(engine: EngineKind) -> Path:
    path = paths.engine_binary_path(engine.value)
    if not path.exists():
        raise EngineNotInstalledError(
            f"{engine.value} is not installed. Run `v2rm core install {engine.value}` first."
        )
    return path


def _read_pid() -> int | None:
    pid_path = paths.pid_file()
    if not pid_path.exists():
        return None
    try:
        return int(pid_path.read_text().strip())
    except (ValueError, OSError):
        return None


def _is_alive(pid: int) -> bool:
    if os.name == "nt":
        return _is_alive_windows(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _is_alive_windows(pid: int) -> bool:
    # os.kill(pid, 0) is not a liveness no-op on Windows (0 == CTRL_C_EVENT),
    # so this dev/test platform needs its own check. The shipped target is
    # Linux, where the os.kill branch above is what actually runs.
    import ctypes

    process_query_limited_information = 0x1000
    still_active = 259
    handle = ctypes.windll.kernel32.OpenProcess(process_query_limited_information, False, pid)
    if not handle:
        return False
    try:
        exit_code = ctypes.c_ulong()
        if not ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
            return False
        return exit_code.value == still_active
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def _cleanup_stale_pidfile() -> None:
    with contextlib.suppress(FileNotFoundError):
        paths.pid_file().unlink()
    with contextlib.suppress(FileNotFoundError):
        paths.engine_meta_file().unlink()


def is_connected() -> tuple[bool, int | None]:
    pid = _read_pid()
    if pid is None:
        return False, None
    if _is_alive(pid):
        return True, pid
    _cleanup_stale_pidfile()
    return False, None


def status() -> dict[str, Any]:
    connected, pid = is_connected()
    meta: dict[str, Any] = {}
    if connected and paths.engine_meta_file().exists():
        with contextlib.suppress(Exception):
            meta = json.loads(paths.engine_meta_file().read_text(encoding="utf-8"))
    return {"connected": connected, "pid": pid, **meta}


def _port_open(port: int, host: str = "127.0.0.1", timeout: float = 0.3) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _probe_address(listen_address: str) -> str:
    """The address to actually connect() to when checking whether the
    engine has started listening. 0.0.0.0/:: aren't valid connect()
    targets even though the engine *is* listening on loopback too in that
    case, so probe 127.0.0.1 instead; a specific non-wildcard address is
    probed directly, since it may not include loopback at all."""
    if listen_address in ("0.0.0.0", "::", ""):
        return "127.0.0.1"
    return listen_address


def _tail_log(n: int = 20) -> str:
    log_path = paths.engine_log_file()
    if not log_path.exists():
        return ""
    lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(lines[-n:])


def connect(
    profile: Profile,
    engine: EngineKind,
    route_plan: RoutePlan,
    socks_port: int,
    http_port: int,
    listen_address: str = "127.0.0.1",
) -> None:
    connected, _ = is_connected()
    if connected:
        disconnect()

    binary = _binary_path(engine)

    from v2rm.engines import generate_config

    config = generate_config(engine, profile, route_plan, socks_port, http_port, listen_address=listen_address)

    paths.run_dir().mkdir(parents=True, exist_ok=True)
    paths.logs_dir().mkdir(parents=True, exist_ok=True)
    config_path = paths.runtime_config_file()
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")

    log_path = paths.engine_log_file()
    if log_path.exists():
        rotated = log_path.with_name(log_path.name + ".1")
        with contextlib.suppress(OSError):
            rotated.unlink()
        with contextlib.suppress(OSError):
            log_path.rename(rotated)

    env = dict(os.environ)
    env["XRAY_LOCATION_ASSET"] = str(paths.geo_assets_dir())

    with log_path.open("wb") as log_fh:
        popen_kwargs: dict[str, Any] = {"stdout": log_fh, "stderr": subprocess.STDOUT, "env": env}
        if os.name == "posix":
            popen_kwargs["start_new_session"] = True
        proc = subprocess.Popen([str(binary), "run", "-c", str(config_path)], **popen_kwargs)

    paths.pid_file().write_text(str(proc.pid), encoding="utf-8")
    paths.engine_meta_file().write_text(
        json.dumps(
            {
                "engine": engine.value,
                "profile_id": profile.id,
                "profile_name": profile.name,
                "listen_address": listen_address,
                "socks_port": socks_port,
                "http_port": http_port,
                "started_at": time.time(),
            }
        ),
        encoding="utf-8",
    )

    probe_host = _probe_address(listen_address)
    deadline = time.monotonic() + CONNECT_POLL_TIMEOUT
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            _cleanup_stale_pidfile()
            raise ConnectFailedError(
                f"{engine.value} exited immediately (code {proc.returncode}). Last log lines:\n{_tail_log()}"
            )
        if _port_open(socks_port, host=probe_host):
            return
        time.sleep(CONNECT_POLL_INTERVAL)

    if proc.poll() is not None:
        _cleanup_stale_pidfile()
    raise ConnectFailedError(
        f"{engine.value} did not start listening on port {socks_port} in time. Last log lines:\n{_tail_log()}"
    )


@contextlib.contextmanager
def run_temporary(
    profile: Profile,
    engine: EngineKind,
    route_plan: RoutePlan,
    socks_port: int,
    http_port: int,
    start_timeout: float = CONNECT_POLL_TIMEOUT,
):
    """Launch a short-lived, throwaway engine instance for real connectivity
    testing. Fully independent of the persistent connection's pidfile/
    config/log -- safe to run several of these concurrently (e.g. `test
    --all`) and safe to run alongside an existing `connect`ed session
    without disturbing it."""
    binary = _binary_path(engine)

    from v2rm.engines import generate_config

    config = generate_config(engine, profile, route_plan, socks_port, http_port)

    with tempfile.TemporaryDirectory(prefix="v2rm-test-") as tmp_dir:
        config_path = Path(tmp_dir) / "config.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        log_path = Path(tmp_dir) / "engine.log"

        env = dict(os.environ)
        env["XRAY_LOCATION_ASSET"] = str(paths.geo_assets_dir())

        with log_path.open("wb") as log_fh:
            popen_kwargs: dict[str, Any] = {"stdout": log_fh, "stderr": subprocess.STDOUT, "env": env}
            if os.name == "posix":
                popen_kwargs["start_new_session"] = True
            proc = subprocess.Popen([str(binary), "run", "-c", str(config_path)], **popen_kwargs)

        try:
            deadline = time.monotonic() + start_timeout
            started = False
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    break
                if _port_open(socks_port):
                    started = True
                    break
                time.sleep(CONNECT_POLL_INTERVAL)

            if not started:
                tail = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
                raise ConnectFailedError(
                    f"{engine.value} did not start in time for the test. Last log lines:\n{tail[-2000:]}"
                )

            yield
        finally:
            if proc.poll() is None:
                with contextlib.suppress(ProcessLookupError):
                    proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    with contextlib.suppress(ProcessLookupError):
                        proc.kill()
                    with contextlib.suppress(subprocess.TimeoutExpired):
                        proc.wait(timeout=3)


def disconnect() -> None:
    pid = _read_pid()
    if pid is None or not _is_alive(pid):
        _cleanup_stale_pidfile()
        raise NotConnectedError("v2rm is not currently connected.")

    with contextlib.suppress(ProcessLookupError):
        os.kill(pid, signal.SIGTERM)

    deadline = time.monotonic() + DISCONNECT_GRACE_SECONDS
    while time.monotonic() < deadline:
        if not _is_alive(pid):
            break
        time.sleep(0.1)
    else:
        with contextlib.suppress(ProcessLookupError, AttributeError):
            os.kill(pid, signal.SIGKILL)

    _cleanup_stale_pidfile()
