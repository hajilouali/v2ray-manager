from __future__ import annotations

import json
import os

import pytest
from typer.testing import CliRunner

from tests.helpers import serverless_profiles
from v2rm.cli.app import app
from v2rm.models.enums import EngineKind, Protocol
from v2rm.models.profile import Profile
from v2rm.process import supervisor
from v2rm.store import paths
from v2rm.store.auth import AuthStore
from v2rm.store.profiles import ProfileStore
from v2rm.store.state import AppStateStore

runner = CliRunner()

UFW_ALLOW = "sudo ufw allow from 172.16.0.0/12 to any port 10808,10809 proto tcp"


class FakeConnect:
    """Stands in for supervisor.connect and records how it was called."""

    def __init__(self):
        self.calls: list[dict] = []
        self.notes: list[str] = []

    def __call__(self, profile, engine, route_plan, socks_port, http_port, listen_address="127.0.0.1", auth=None):
        self.calls.append(
            {"profile": profile, "engine": engine, "route_plan": route_plan, "socks": socks_port,
             "http": http_port, "listen": listen_address, "auth": auth}
        )
        return list(self.notes)


@pytest.fixture
def fake_connect(monkeypatch):
    fake = FakeConnect()
    monkeypatch.setattr(supervisor, "connect", fake)
    return fake


def add_profile(profile: Profile) -> Profile:
    return ProfileStore().add(profile)


def trojan(name="trojan-1") -> Profile:
    return add_profile(Profile(name=name, protocol=Protocol.TROJAN, server="t.example.com", port=443, password="pw"))


def raw() -> Profile:
    profile = serverless_profiles()[0]
    profile.id = ""
    return add_profile(profile)


def hysteria2() -> Profile:
    return add_profile(Profile(name="hy2", protocol=Protocol.HYSTERIA2, server="h.example.com", port=443, password="pw"))


# ---- connect --------------------------------------------------------------------------------------


def test_connect_passes_the_saved_configuration_and_remembers_the_profile(fake_connect):
    profile = trojan()
    result = runner.invoke(app, ["connect", "trojan-1"])
    assert result.exit_code == 0, result.output

    (call,) = fake_connect.calls
    assert call["profile"].id == profile.id
    assert call["engine"] == EngineKind.XRAY
    assert (call["socks"], call["http"], call["listen"], call["auth"]) == (10808, 10809, "127.0.0.1", None)
    assert "Connected via xray -> trojan-1" in result.output
    assert AppStateStore().load().active_profile_id == profile.id
    assert "Warning" not in result.output and "login" not in result.output


def test_connect_does_not_change_the_saved_default_engine(fake_connect):
    trojan()
    runner.invoke(app, ["connect", "trojan-1"])
    assert AppStateStore().load().active_engine is None


def test_connect_with_no_active_profile_says_what_to_do(fake_connect):
    result = runner.invoke(app, ["connect"])
    assert result.exit_code != 0
    assert "No active profile" in str(result.exception)
    assert fake_connect.calls == []


def test_the_default_engine_is_used_for_ordinary_profiles(fake_connect):
    trojan()
    runner.invoke(app, ["core", "use", "singbox"])
    result = runner.invoke(app, ["connect", "trojan-1"])
    assert fake_connect.calls[0]["engine"] == EngineKind.SINGBOX
    assert "Using " not in result.output  # no engine note: nothing was overridden


def test_a_raw_profile_runs_on_xray_even_when_singbox_is_the_default(fake_connect):
    raw()
    runner.invoke(app, ["core", "use", "singbox"])
    result = runner.invoke(app, ["connect", serverless_profiles()[0].name])
    assert result.exit_code == 0, result.output
    assert fake_connect.calls[0]["engine"] == EngineKind.XRAY
    assert "Using Xray-core for this raw Xray profile" in result.output
    assert AppStateStore().load().active_engine == EngineKind.SINGBOX  # the user's choice is untouched


def test_a_hysteria2_profile_runs_on_singbox_even_when_xray_is_the_default(fake_connect):
    hysteria2()
    runner.invoke(app, ["core", "use", "xray"])
    result = runner.invoke(app, ["connect", "hy2"])
    assert fake_connect.calls[0]["engine"] == EngineKind.SINGBOX
    assert "Using sing-box for this hysteria2 profile" in result.output


def test_a_raw_profile_connect_says_routing_presets_do_not_apply(fake_connect):
    raw()
    result = runner.invoke(app, ["connect", serverless_profiles()[0].name])
    assert "route presets are not applied to raw configs" in result.output


def test_other_profiles_do_not_get_the_raw_routing_note(fake_connect):
    trojan()
    assert "not applied to raw" not in runner.invoke(app, ["connect", "trojan-1"]).output


def test_generator_notes_are_shown(fake_connect):
    trojan()
    fake_connect.notes = ["Ignored inbound(s) in this raw config: tun 'tun-in'."]
    result = runner.invoke(app, ["connect", "trojan-1"])
    assert "Note: Ignored inbound(s) in this raw config: tun 'tun-in'." in result.output


def test_the_saved_login_is_applied_and_mentioned(fake_connect):
    trojan()
    runner.invoke(app, ["port", "set", "--auth", "demo:pw"])
    result = runner.invoke(app, ["connect", "trojan-1"])
    assert fake_connect.calls[0]["auth"] == AuthStore().load()
    assert "login required" in result.output
    assert "pw" not in result.output.replace("login required", "")


def test_listening_beyond_localhost_warns_and_gives_the_firewall_commands_without_a_login(fake_connect):
    trojan()
    runner.invoke(app, ["port", "set", "--listen", "172.17.0.1"])
    result = runner.invoke(app, ["connect", "trojan-1"])
    assert result.exit_code == 0, result.output
    assert fake_connect.calls[0]["listen"] == "172.17.0.1"
    assert "Warning" in result.output and "no authentication" in result.output
    assert UFW_ALLOW in result.output


def test_with_a_login_the_open_proxy_warning_is_not_shown(fake_connect):
    trojan()
    runner.invoke(app, ["port", "set", "--listen", "0.0.0.0", "--auth", "demo:pw"])
    result = runner.invoke(app, ["connect", "trojan-1"])
    assert "Warning" in result.output and "all interfaces" in result.output
    assert "no authentication" not in result.output


def test_a_saved_listen_address_that_has_disappeared_is_reported_before_anything_starts(fake_connect, host_addresses):
    trojan()
    runner.invoke(app, ["port", "set", "--listen", "172.17.0.1"])
    host_addresses.discard("172.17.0.1")  # Docker stopped
    result = runner.invoke(app, ["connect", "trojan-1"])
    assert result.exit_code != 0
    assert "no address 172.17.0.1" in str(result.exception)
    assert "v2rm port set --listen" in str(result.exception)
    assert fake_connect.calls == []


def test_profile_names_with_brackets_are_printed_literally(fake_connect):
    trojan("[free] node")
    result = runner.invoke(app, ["connect", "[free] node"])
    assert "-> [free] node" in result.output


# ---- status ---------------------------------------------------------------------------------------------


def fake_running(monkeypatch, listening=True, **meta):
    paths.run_dir().mkdir(parents=True, exist_ok=True)
    paths.pid_file().write_text(str(os.getpid()))
    base = {"engine": "xray", "profile_name": "Demo", "profile_kind": "trojan", "listen_address": "127.0.0.1",
            "socks_port": 10808, "http_port": 10809, "authenticated": False}
    base.update(meta)
    paths.engine_meta_file().write_text(json.dumps(base))
    monkeypatch.setattr(supervisor, "_port_open", lambda port, host="127.0.0.1", timeout=0.3: listening)


def test_status_when_not_connected():
    assert "Not connected" in runner.invoke(app, ["status"]).output


def test_status_shows_the_basics(monkeypatch):
    fake_running(monkeypatch)
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0, result.output
    for expected in ("Demo", "(trojan)", "xray", "127.0.0.1:10808", "127.0.0.1:10809", "login     none", "routing   global"):
        assert expected in result.output
    assert "Warning" not in result.output and "nothing is accepting" not in result.output


def test_status_for_a_raw_profile_says_presets_do_not_apply(monkeypatch):
    fake_running(monkeypatch, profile_kind="raw")
    result = runner.invoke(app, ["status"])
    assert "(raw)" in result.output
    assert "the config's own rules" in result.output
    assert "route presets are not applied to raw configs" in result.output


def test_status_reports_an_engine_that_is_running_but_not_listening(monkeypatch):
    fake_running(monkeypatch, listening=False)
    result = runner.invoke(app, ["status"])
    assert "nothing is accepting connections on 127.0.0.1:10808" in result.output


def test_status_warns_briefly_about_an_open_proxy(monkeypatch):
    fake_running(monkeypatch, listen_address="172.17.0.1")
    result = runner.invoke(app, ["status"])
    assert "172.17.0.1:10808" in result.output
    assert "Warning" in result.output and "no authentication" in result.output
    assert "v2rm doctor" in result.output
    assert UFW_ALLOW not in result.output


def test_status_with_a_login_shows_it_and_skips_the_open_proxy_warning(monkeypatch):
    fake_running(monkeypatch, listen_address="0.0.0.0", authenticated=True)
    result = runner.invoke(app, ["status"])
    assert "login     required" in result.output
    assert "Warning" in result.output and "no authentication" not in result.output


def test_status_of_a_connection_started_by_an_older_version_still_works(monkeypatch):
    paths.run_dir().mkdir(parents=True, exist_ok=True)
    paths.pid_file().write_text(str(os.getpid()))
    paths.engine_meta_file().write_text(json.dumps({"engine": "xray", "profile_name": "Old"}))
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0, result.output
    assert "Old" in result.output
