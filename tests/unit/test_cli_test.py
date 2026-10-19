from __future__ import annotations

import contextlib

import pytest
from typer.testing import CliRunner

from tests.helpers import serverless_profiles
from v2rm.cli.app import app
from v2rm.errors import CoreTooOldError
from v2rm.models.enums import EngineKind, Protocol
from v2rm.models.profile import Profile
from v2rm.net import speedtest
from v2rm.store.auth import AuthStore
from v2rm.store.profiles import ProfileStore

runner = CliRunner()


def test_test_command_reports_engine_not_installed():
    add = runner.invoke(app, ["add", "trojan://pw@t.example.com:443?security=tls#TestMe"])
    assert add.exit_code == 0, add.output

    result = runner.invoke(app, ["test", "TestMe"])
    assert result.exit_code == 0, result.output
    assert "FAIL" in result.output
    assert "not installed" in result.output


def test_test_all_with_no_profiles():
    result = runner.invoke(app, ["test", "--all"])
    assert result.exit_code == 0, result.output
    assert "No profiles" in result.output


def test_test_all_reports_each_profile_failure():
    runner.invoke(app, ["add", "trojan://pw@a.example.com:443?security=tls#A"])
    runner.invoke(app, ["add", "trojan://pw@b.example.com:443?security=tls#B"])

    result = runner.invoke(app, ["test", "--all", "--concurrency", "2"])
    assert result.exit_code == 0, result.output
    assert "A" in result.output
    assert "B" in result.output
    assert "FAIL" in result.output


def test_test_requires_ref_or_all():
    result = runner.invoke(app, ["test"])
    assert result.exit_code != 0


# ---- engine choice, login, raw/serverless notes ----------------------------------------------------------

class FakeTemporary:
    """Stands in for supervisor.run_temporary."""

    def __init__(self):
        self.calls: list[dict] = []
        self.raises: Exception | None = None
        self.notes: list[str] = []

    def __call__(self, profile, engine, route_plan, socks_port, http_port, start_timeout=2.0, auth=None, notes=None):
        self.calls.append({"profile": profile, "engine": engine, "socks": socks_port, "http": http_port, "auth": auth})
        if self.raises:
            raise self.raises
        if notes is not None:
            notes.extend(self.notes)
        return contextlib.nullcontext()


@pytest.fixture
def stubbed(monkeypatch):
    temporary = FakeTemporary()
    monkeypatch.setattr("v2rm.cli.test.supervisor.run_temporary", temporary)
    probes: list[dict] = []

    def fake_probe(socks_port, timeout=10.0, auth=None, **kwargs):
        probes.append({"socks": socks_port, "auth": auth})
        return speedtest.TestResult(ok=True, latency_ms=42.0, throughput_mbps=12.5, url="http://example.test/file")

    monkeypatch.setattr("v2rm.cli.test.run_connectivity_test", fake_probe)
    temporary.probes = probes
    return temporary


def add_raw() -> Profile:
    profile = serverless_profiles()[0]
    profile.id = ""
    return ProfileStore().add(profile)


def add_trojan(name="trojan-1") -> Profile:
    return ProfileStore().add(Profile(name=name, protocol=Protocol.TROJAN, server="t.example.com", port=443, password="pw"))


def test_a_test_uses_ephemeral_loopback_ports_and_the_global_preset(stubbed):
    add_trojan()
    result = runner.invoke(app, ["test", "trojan-1"])
    assert result.exit_code == 0, result.output
    (call,) = stubbed.calls
    assert call["socks"] != call["http"]
    assert stubbed.probes[0]["socks"] == call["socks"]
    assert "OK" in result.output and "42 ms" in result.output


def test_the_proxy_login_is_used_by_the_throwaway_engine_and_the_download(stubbed):
    add_trojan()
    runner.invoke(app, ["port", "set", "--auth", "demo:pw"])
    runner.invoke(app, ["test", "trojan-1"])
    assert stubbed.calls[0]["auth"] == AuthStore().load()
    assert stubbed.probes[0]["auth"] == AuthStore().load()


def test_no_login_means_none_is_passed(stubbed):
    add_trojan()
    runner.invoke(app, ["test", "trojan-1"])
    assert stubbed.calls[0]["auth"] is None and stubbed.probes[0]["auth"] is None


def test_a_raw_profile_is_tested_on_xray_even_if_singbox_is_the_default(stubbed):
    add_raw()
    runner.invoke(app, ["core", "use", "singbox"])
    runner.invoke(app, ["test", serverless_profiles()[0].name])
    assert stubbed.calls[0]["engine"] == EngineKind.XRAY


def test_an_ordinary_profile_is_tested_on_the_default_engine(stubbed):
    add_trojan()
    runner.invoke(app, ["core", "use", "singbox"])
    runner.invoke(app, ["test", "trojan-1"])
    assert stubbed.calls[0]["engine"] == EngineKind.SINGBOX


def test_a_serverless_result_is_explained_as_a_direct_connection(stubbed):
    add_raw()
    result = runner.invoke(app, ["test", serverless_profiles()[0].name])
    assert result.exit_code == 0, result.output
    assert "not a tunnel" in result.output
    assert "does not hide your IP address" in result.output


def test_an_ordinary_profile_gets_no_serverless_note(stubbed):
    add_trojan()
    assert "not a tunnel" not in runner.invoke(app, ["test", "trojan-1"]).output


def test_the_serverless_note_appears_once_after_a_batch(stubbed):
    for profile in serverless_profiles():
        profile.id = ""
        ProfileStore().add(profile)
    add_trojan()
    result = runner.invoke(app, ["test", "--all"])
    assert result.output.count("not a tunnel") == 1


def test_the_batch_table_has_a_type_column_and_a_dash_for_a_raw_server(stubbed):
    add_raw()
    add_trojan()
    result = runner.invoke(app, ["test", "--all"])
    header = next(line for line in result.output.splitlines() if "Latency" in line)
    assert "Type" in header and "Protocol" not in header
    raw_row = next(line for line in result.output.splitlines() if serverless_profiles()[0].name[:20] in line)
    assert " raw " in raw_row and "—" in raw_row
    trojan_row = next(line for line in result.output.splitlines() if "trojan-1" in line)
    assert " trojan " in trojan_row and "t.example.com" in trojan_row


def test_protocol_filter_accepts_the_type_names_shown_in_the_table(stubbed):
    add_raw()
    add_trojan()
    for value in ("raw", "raw-xray"):
        stubbed.calls.clear()
        runner.invoke(app, ["test", "--all", "--protocol", value])
        assert [c["profile"].protocol for c in stubbed.calls] == [Protocol.RAW_XRAY]
    stubbed.calls.clear()
    runner.invoke(app, ["test", "--all", "--protocol", "trojan"])
    assert [c["profile"].protocol for c in stubbed.calls] == [Protocol.TROJAN]


def test_a_too_old_core_is_a_failed_result_with_the_fix_not_a_crash(stubbed):
    add_raw()
    stubbed.raises = CoreTooOldError("'x' needs Xray-core >= 26.6.27, but v26.3.27 is installed. Run `v2rm core update xray`.")
    result = runner.invoke(app, ["test", serverless_profiles()[0].name])
    assert result.exit_code == 0, result.output
    assert "FAIL" in result.output and "v2rm core update xray" in result.output


def test_generator_notes_are_shown_for_a_single_test(stubbed):
    add_trojan()
    stubbed.notes = ["Ignored inbound(s) in this raw config: tun 'tun-in'."]
    assert "Note: Ignored inbound(s)" in runner.invoke(app, ["test", "trojan-1"]).output


def test_bracketed_profile_names_are_printed_literally(stubbed):
    add_trojan("[free] node")
    single = runner.invoke(app, ["test", "[free] node"])
    assert "OK [free] node" in single.output
    batch = runner.invoke(app, ["test", "--all"])
    assert "[free] node" in batch.output
