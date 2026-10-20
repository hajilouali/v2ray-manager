"""connect / status / test for Aether profiles and chains (the supervisor is stubbed: the real
start-up is covered by test_stack_run.py)."""

from __future__ import annotations

import json
import os

import pytest
from typer.testing import CliRunner

from v2rm.cli.app import app
from v2rm.errors import ConnectFailedError
from v2rm.models.aether import AetherMode, AetherSettings
from v2rm.models.auth import ProxyAuth
from v2rm.models.chain import HOP_PROFILE, ChainHop
from v2rm.models.enums import Protocol
from v2rm.models.profile import Profile
from v2rm.net import speedtest
from v2rm.process import supervisor
from v2rm.store import paths
from v2rm.store.auth import AuthStore
from v2rm.store.profiles import ProfileStore
from v2rm.store.state import AppStateStore

runner = CliRunner()


class FakeConnectStack:
    def __init__(self):
        self.calls: list[dict] = []
        self.notes: list[str] = []
        self.progress_lines: list[str] = []
        self.raises: BaseException | None = None

    def __call__(
        self, profile, preferred_engine, route_plan, socks_port, http_port, listen_address="127.0.0.1",
        auth=None, progress=None, store=None,
    ):
        self.calls.append(
            {"profile": profile, "socks": socks_port, "http": http_port, "listen": listen_address, "auth": auth,
             "route": route_plan.name}
        )
        for line in self.progress_lines:
            progress(line)
        if self.raises:
            raise self.raises
        return list(self.notes)


@pytest.fixture
def fake_stack(monkeypatch):
    fake = FakeConnectStack()
    monkeypatch.setattr(supervisor, "connect_stack", fake)
    return fake


def add_aether(name="WARP", **settings) -> Profile:
    return ProfileStore().add(Profile(name=name, protocol=Protocol.AETHER, aether=AetherSettings(**settings)))


def add_trojan(name="trojan") -> Profile:
    return ProfileStore().add(
        Profile(name=name, protocol=Protocol.TROJAN, server=f"{name}.example.com", port=443, password="pw")
    )


def add_chain(name, *members) -> Profile:
    hops = [ChainHop(HOP_PROFILE, m.id, m.name) for m in members]
    return ProfileStore().add(Profile(name=name, protocol=Protocol.CHAIN, chain=hops))


# ---- connect --------------------------------------------------------------------------------------------


def test_connecting_an_aether_profile_uses_the_stack_path(fake_stack):
    warp = add_aether()
    result = runner.invoke(app, ["connect", "WARP"])
    assert result.exit_code == 0, result.output

    (call,) = fake_stack.calls
    assert call["profile"].id == warp.id
    assert (call["socks"], call["http"], call["listen"], call["auth"], call["route"]) == (10808, 10809, "127.0.0.1", None, "global")
    assert "Connected via aether -> WARP" in result.output
    assert AppStateStore().load().active_profile_id == warp.id


def test_the_wait_note_and_progress_lines_are_shown(fake_stack):
    add_aether()
    fake_stack.progress_lines = ["Starting WARP (aether)...", "WARP (aether): [+] using cloudflare edge 162.159.198.1:443"]
    result = runner.invoke(app, ["connect", "WARP"])
    assert "looking for a working Cloudflare gateway" in result.output
    assert "Starting WARP (aether)..." in result.output
    assert "using cloudflare edge 162.159.198.1:443" in result.output


def test_a_first_connection_says_it_will_register_a_device_before_the_wait_and_only_once(fake_stack):
    add_aether()
    fake_stack.notes = ["First connection of 'WARP': Aether registers a free anonymous Cloudflare WARP device for it"]
    result = runner.invoke(app, ["connect", "WARP"])
    assert result.exit_code == 0, result.output
    assert result.output.count("First connection of") == 1
    assert result.output.index("First connection of") < result.output.index("looking for a working Cloudflare gateway")


def test_no_registration_notice_once_the_identity_exists(fake_stack):
    warp = add_aether()
    identity = paths.aether_profile_dir(warp.id) / "aether-masque.toml"
    identity.parent.mkdir(parents=True)
    identity.write_text("keys")
    result = runner.invoke(app, ["connect", "WARP"])
    assert "First connection of" not in result.output


def test_notes_from_the_stack_are_shown(fake_stack):
    add_aether()
    fake_stack.notes = ["Using the HTTP/2 (TCP) carrier through the previous hop of the chain."]
    result = runner.invoke(app, ["connect", "WARP"])
    assert "Note: Using the HTTP/2 (TCP) carrier" in result.output


def test_connecting_a_chain_says_so_and_lists_the_hops(fake_stack):
    warp, server = add_aether(), add_trojan()
    add_chain("warp-then-trojan", warp, server)
    result = runner.invoke(app, ["connect", "warp-then-trojan"])
    assert result.exit_code == 0, result.output
    assert "Connected via chain -> warp-then-trojan" in result.output
    assert "WARP -> trojan" in result.output


def test_a_chain_of_plain_profiles_needs_no_aether_note(fake_stack):
    add_chain("c", add_trojan("one"), add_trojan("two"))
    result = runner.invoke(app, ["connect", "c"])
    assert result.exit_code == 0, result.output
    assert "looking for a working Cloudflare gateway" not in result.output


def test_the_login_and_listen_address_reach_the_stack(fake_stack):
    add_aether()
    AuthStore().save(ProxyAuth("user", "pw"))
    state_store = AppStateStore()
    state = state_store.load()
    state.listen_address = "172.17.0.1"
    state.route_preset = state.route_preset.__class__("bypass-ir")
    state_store.save(state)

    result = runner.invoke(app, ["connect", "WARP"])
    assert result.exit_code == 0, result.output
    (call,) = fake_stack.calls
    assert call["auth"] == ProxyAuth("user", "pw") and call["listen"] == "172.17.0.1" and call["route"] == "bypass-ir"
    assert "login required" in result.output


def test_ctrl_c_while_waiting_cancels_cleanly(fake_stack):
    add_aether()
    fake_stack.raises = KeyboardInterrupt()
    result = runner.invoke(app, ["connect", "WARP"])
    assert result.exit_code == 130
    assert "Cancelled" in result.output
    assert AppStateStore().load().active_profile_id is None


def test_a_failed_connection_is_reported_and_not_remembered(fake_stack):
    add_aether()
    fake_stack.raises = ConnectFailedError("WARP (aether) exited (code 1)")
    result = runner.invoke(app, ["connect", "WARP"])
    assert result.exit_code != 0 and "exited (code 1)" in str(result.exception)
    assert AppStateStore().load().active_profile_id is None


def test_an_ordinary_profile_still_takes_the_ordinary_path(monkeypatch, fake_stack):
    trojan = add_trojan()
    seen = []
    monkeypatch.setattr(supervisor, "connect", lambda *a, **k: seen.append(a[0].id) or [])
    result = runner.invoke(app, ["connect", "trojan"])
    assert result.exit_code == 0, result.output
    assert seen == [trojan.id] and fake_stack.calls == []


# ---- status -----------------------------------------------------------------------------------------------


def write_state(meta: dict) -> None:
    paths.run_dir().mkdir(parents=True, exist_ok=True)
    paths.pid_file().write_text(str(os.getpid()))
    paths.engine_meta_file().write_text(json.dumps(meta))


def member(label, engine="aether", pid=None, port=41000, facing=False, log="/logs/x.log"):
    return {"label": label, "engine": engine, "pid": pid or os.getpid(), "listen": "127.0.0.1", "socks_port": port,
            "user_facing": facing, "log": log}


def test_status_lists_the_programs_of_a_chain():
    write_state(
        {
            "engine": "xray", "profile_name": "c", "profile_kind": "chain", "listen_address": "127.0.0.1",
            "socks_port": 1, "http_port": 2, "state": "running", "hops": ["WARP", "trojan"], "aether_ids": [],
            "stack": [member("WARP (aether)"), member("trojan (xray)", "xray", port=1, facing=True)],
        }
    )
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0, result.output
    out = result.output
    assert "Connected" in out and "chain" in out and "WARP -> trojan" in out
    assert "1. WARP (aether)" in out and "2. trojan (xray)" in out and "serves your ports" in out


def test_status_says_when_a_hop_has_stopped():
    write_state(
        {
            "engine": "xray", "profile_name": "c", "profile_kind": "chain", "listen_address": "127.0.0.1",
            "socks_port": 1, "http_port": 2, "state": "running", "hops": ["WARP", "trojan"],
            "stack": [member("WARP (aether)", pid=2_000_000_000, log="/logs/stage-0-aether.log"),
                      member("trojan (xray)", "xray", port=1, facing=True)],
        }
    )
    out = runner.invoke(app, ["status"]).output
    assert "stopped" in out and "WARP (aether) has stopped" in out and "/logs/stage-0-aether.log" in out
    assert "v2rm connect" in out


def test_status_while_a_connection_is_still_starting():
    write_state(
        {"engine": "aether", "profile_name": "W", "profile_kind": "aether", "listen_address": "127.0.0.1",
         "socks_port": 1, "http_port": 2, "state": "starting", "hops": ["W"], "stack": [member("W (aether)", facing=True)]}
    )
    out = runner.invoke(app, ["status"]).output
    assert "Starting..." in out and "still starting" in out
    assert "nothing is accepting connections" not in out  # it is not supposed to be up yet


def test_status_shows_the_gateway_aether_remembers():
    warp = add_aether()
    cache = paths.aether_profile_dir(warp.id) / "aether-masque-lastconn.toml"
    cache.parent.mkdir(parents=True)
    cache.write_text('peer = "162.159.198.1:443"\nprofile = "gfw"\ncarrier = "masque-h3"\nrecent = ["162.159.198.1:443"]\n')
    write_state(
        {"engine": "aether", "profile_name": "WARP", "profile_kind": "aether", "listen_address": "127.0.0.1",
         "socks_port": 1, "http_port": 2, "state": "running", "hops": ["WARP"], "aether_ids": [warp.id],
         "stack": [member("WARP (aether)", facing=True)]}
    )
    out = runner.invoke(app, ["status"]).output
    assert "162.159.198.1:443" in out and "remembered for quick reconnect" in out


def test_status_of_a_mode_with_no_gateway_memory_says_it_scans_again():
    warp = add_aether(mode=AetherMode.GOOL_CLASSIC)
    write_state(
        {"engine": "aether", "profile_name": "WARP", "profile_kind": "aether", "listen_address": "127.0.0.1",
         "socks_port": 1, "http_port": 2, "state": "running", "hops": ["WARP"], "aether_ids": [warp.id],
         "stack": [member("WARP (aether)", facing=True)]}
    )
    assert "scans again after a restart" in runner.invoke(app, ["status"]).output


# ---- test -------------------------------------------------------------------------------------------------


@pytest.fixture
def fake_temp_stack(monkeypatch):
    import contextlib

    calls: list[dict] = []

    @contextlib.contextmanager
    def run(profile, preferred_engine, socks_port, http_port, start_timeout=2.0, auth=None, notes=None, progress=None, store=None):
        calls.append({"profile": profile, "socks": socks_port, "auth": auth})
        if notes is not None:
            notes.append("First connection of 'x'")
        if progress:
            progress("x (aether): [+] using cloudflare edge 1.1.1.1:443")
        yield None

    monkeypatch.setattr(supervisor, "run_temporary_stack", run)
    monkeypatch.setattr(
        "v2rm.cli.test.run_connectivity_test",
        lambda port, timeout=10.0, auth=None, urls=None: speedtest.TestResult(ok=True, latency_ms=120, throughput_mbps=3.5, url="u"),
    )
    return calls


def test_testing_an_aether_profile_starts_a_throwaway_stack(fake_temp_stack):
    add_aether()
    result = runner.invoke(app, ["test", "WARP"])
    assert result.exit_code == 0, result.output
    assert "OK WARP" in result.output and "120 ms" in result.output
    assert "can take a minute or two" in result.output
    assert "using cloudflare edge 1.1.1.1:443" in result.output
    assert "Note: First connection" in result.output
    assert len(fake_temp_stack) == 1


def test_a_connected_profile_is_tested_through_its_live_proxy(fake_temp_stack, monkeypatch):
    warp = add_aether()
    ports: list[int] = []
    monkeypatch.setattr(
        "v2rm.cli.test.run_connectivity_test",
        lambda port, timeout=10.0, auth=None, urls=None: ports.append(port) or speedtest.TestResult(ok=True, latency_ms=5, throughput_mbps=1, url="u"),
    )
    write_state(
        {"engine": "aether", "profile_id": warp.id, "profile_name": "WARP", "profile_kind": "aether",
         "listen_address": "127.0.0.1", "socks_port": 10808, "http_port": 10809, "state": "running",
         "aether_ids": [warp.id], "stack": [member("WARP (aether)", facing=True)]}
    )
    result = runner.invoke(app, ["test", "WARP"])
    assert result.exit_code == 0, result.output
    assert ports == [10808] and fake_temp_stack == []  # no second tunnel


def test_a_profile_sharing_a_live_identity_is_not_tested(fake_temp_stack):
    warp, server = add_aether(), add_trojan()
    chain = add_chain("c", warp, server)
    write_state(
        {"engine": "xray", "profile_id": chain.id, "profile_name": "c", "profile_kind": "chain",
         "listen_address": "127.0.0.1", "socks_port": 10808, "http_port": 10809, "state": "running",
         "aether_ids": [warp.id], "stack": [member("WARP (aether)"), member("trojan (xray)", "xray", facing=True)]}
    )
    result = runner.invoke(app, ["test", "WARP"])
    assert "not tested" in result.output and "same WARP identity" in result.output
    assert fake_temp_stack == []


def test_a_failing_stack_is_a_failed_test_not_a_crash(monkeypatch):
    import contextlib

    @contextlib.contextmanager
    def broken(*args, **kwargs):
        raise ConnectFailedError("WARP (aether) exited (code 1) before it was ready")
        yield  # pragma: no cover

    monkeypatch.setattr(supervisor, "run_temporary_stack", broken)
    add_aether()
    result = runner.invoke(app, ["test", "WARP"])
    assert "FAIL WARP" in result.output and "exited (code 1)" in result.output


def test_test_all_includes_stack_profiles(fake_temp_stack):
    add_aether(), add_trojan()
    import v2rm.cli.test as cli_test

    calls = []
    original = cli_test._test_one
    cli_test._test_one = lambda p, *a, **k: calls.append(p.name) or speedtest.TestResult(ok=True, latency_ms=1, throughput_mbps=1, url="u")
    try:
        result = runner.invoke(app, ["test", "--all"])
    finally:
        cli_test._test_one = original
    assert result.exit_code == 0, result.output
    assert sorted(calls) == ["WARP", "trojan"]
