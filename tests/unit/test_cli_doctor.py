from __future__ import annotations

import os

import pytest
from typer.testing import CliRunner

from tests.helpers import serverless_profiles
from v2rm.cli import doctor
from v2rm.cli.app import app
from v2rm.engines.probe import FeatureProbe
from v2rm.net.firewall import BLOCKED, INACTIVE, OPEN, RESTRICTED, UNKNOWN, FirewallReport
from v2rm.process import supervisor
from v2rm.store import paths
from v2rm.store.profiles import ProfileStore

runner = CliRunner()

UFW_ALLOW = "sudo ufw allow from 172.16.0.0/12 to any port 10808,10809 proto tcp"


def test_doctor_runs_and_reports_checks():
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0, result.output
    assert "xray" in result.output
    assert "singbox" in result.output
    assert "Not connected" in result.output


@pytest.fixture
def xray_installed(monkeypatch):
    """Xray v26.3.27 is 'installed', its probes answer as set in `probes`."""
    probes = [FeatureProbe("masque", True, "a MASQUE outbound config was accepted"),
              FeatureProbe("finalmask", True, "finalmask configs are accepted, and invalid masks are rejected")]
    monkeypatch.setattr(doctor, "current_version", lambda engine: "v26.3.27" if engine == "xray" else None)
    monkeypatch.setattr(doctor, "probe_xray_features", lambda binary, assets: probes)
    binary = paths.engine_binary_path("xray")
    binary.parent.mkdir(parents=True, exist_ok=True)
    binary.write_text("")
    return probes


def messages() -> list[str]:
    return [c.message for c in doctor.collect_checks()]


def find(fragment: str) -> doctor.Check:
    matching = [c for c in doctor.collect_checks() if fragment in c.message]
    assert matching, f"no check mentions {fragment!r}: {[c.message for c in doctor.collect_checks()]}"
    return matching[0]


# ---- Xray -------------------------------------------------------------------------------------------------


def test_the_xray_version_and_feature_support_are_reported(xray_installed):
    assert find("xray installed (v26.3.27)").ok
    assert find("Xray masque: supported").ok
    assert find("Xray finalmask: supported").ok


def test_unsupported_features_are_warned_about_with_the_fix(xray_installed):
    xray_installed[0] = FeatureProbe("masque", False, "this Xray doesn't know the masque outbound (unknown config id: masque)")
    check = find("Xray masque: not supported")
    assert not check.ok and "v2rm core update xray" in check.hints[0]


def test_an_unclear_probe_is_a_warning_that_says_so(xray_installed):
    xray_installed[1] = FeatureProbe("finalmask", None, "unclear -- Xray accepted an invalid mask type as well")
    check = find("Xray finalmask: unclear")
    assert not check.ok


def test_probes_are_skipped_when_xray_is_not_installed():
    assert not any("Xray masque" in m or "Xray finalmask" in m for m in messages())


def test_geo_assets_location_is_shown_when_present(xray_installed):
    assets = paths.geo_assets_dir()
    assets.mkdir(parents=True, exist_ok=True)
    (assets / "geoip.dat").write_bytes(b"x")
    (assets / "geosite.dat").write_bytes(b"x")
    check = find("Geo data in")
    assert check.ok and str(assets) in check.message


def test_missing_geo_assets_are_reported_with_the_command(xray_installed):
    assets = paths.geo_assets_dir()
    assets.mkdir(parents=True, exist_ok=True)
    (assets / "geoip.dat").write_bytes(b"x")
    check = find("Geo data missing")
    assert not check.ok
    assert "geosite.dat" in check.message and "geoip.dat" not in check.message.split("missing in")[1]
    assert "v2rm route update-data" in check.message


def test_profiles_needing_a_newer_xray_are_listed(xray_installed):
    for profile in serverless_profiles():
        profile.id = ""
        ProfileStore().add(profile)
    check = find("need a newer Xray-core than v26.3.27")
    assert not check.ok
    assert check.message.startswith("2 profile(s)")
    assert "Serverless-v52-fragA (needs >= 26.6.27)" in check.message
    assert "v2rm core update xray" in check.hints[0]


def test_no_such_warning_when_the_installed_core_is_new_enough(monkeypatch, xray_installed):
    monkeypatch.setattr(doctor, "current_version", lambda engine: "v26.6.27" if engine == "xray" else None)
    for profile in serverless_profiles():
        profile.id = ""
        ProfileStore().add(profile)
    assert not any("need a newer Xray-core" in m for m in messages())


def test_ordinary_profiles_never_trigger_the_version_warning(xray_installed):
    runner.invoke(app, ["add", "trojan://pw@t.example.com:443?security=tls#T"])
    assert not any("need a newer Xray-core" in m for m in messages())


# ---- who can reach the proxy -----------------------------------------------------------------------------


@pytest.fixture
def firewall(monkeypatch):
    answer = {"report": FirewallReport(None, UNKNOWN, "no ufw or iptables command found")}
    calls = []

    def fake(ports):
        calls.append(list(ports))
        return answer["report"]

    monkeypatch.setattr(doctor, "check_firewall", fake)
    answer["calls"] = calls
    return answer


def test_loopback_needs_no_exposure_checks(firewall):
    assert find("localhost only").ok
    assert firewall["calls"] == []
    assert not any("Firewall" in m for m in messages())


def test_listening_beyond_localhost_warns_and_checks_the_firewall_for_both_ports(firewall):
    runner.invoke(app, ["port", "set", "--listen", "172.17.0.1"])
    assert not find("Listening on 172.17.0.1, not just localhost").ok
    assert firewall["calls"] == [[10808, 10809]]


def test_without_a_login_the_commands_to_close_it_are_shown(firewall):
    runner.invoke(app, ["port", "set", "--listen", "0.0.0.0"])
    check = find("No login is required")
    assert not check.ok
    assert any(UFW_ALLOW in hint for hint in check.hints)
    assert any("v2rm port set --auth USER:PASS" in hint for hint in check.hints)


def test_with_a_login_it_says_so_and_stops_nagging(firewall):
    runner.invoke(app, ["port", "set", "--listen", "0.0.0.0", "--auth", "demo:pw"])
    assert find("Login required on both ports (user: demo)").ok
    assert not any("No login is required" in m for m in messages())
    assert "pw" not in " ".join(messages()).replace("Login required", "")


def test_a_restricting_firewall_is_a_pass(firewall):
    runner.invoke(app, ["port", "set", "--listen", "0.0.0.0"])
    firewall["report"] = FirewallReport("ufw", RESTRICTED, "ufw allows ports 10808 and 10809 only from 172.16.0.0/12")
    check = find("Firewall (ufw)")
    assert check.ok and "only from 172.16.0.0/12" in check.message


@pytest.mark.parametrize("state", [OPEN, INACTIVE])
def test_an_open_or_absent_firewall_is_a_warning(firewall, state):
    runner.invoke(app, ["port", "set", "--listen", "0.0.0.0"])
    firewall["report"] = FirewallReport("ufw", state, "ufw allows ports 10808 and 10809 from anywhere")
    assert not find("Firewall").ok


def test_a_blocking_firewall_explains_that_containers_cannot_connect_yet(firewall):
    runner.invoke(app, ["port", "set", "--listen", "172.17.0.1", "--auth", "demo:pw"])
    firewall["report"] = FirewallReport("ufw", BLOCKED, "no ufw rule allows ports 10808 and 10809 and the default for incoming is deny")
    check = find("Firewall (ufw)")
    assert not check.ok
    assert "containers can't connect until you allow them" in check.message
    assert UFW_ALLOW in " ".join(check.hints)


def test_an_unknown_firewall_says_it_could_not_determine(firewall):
    runner.invoke(app, ["port", "set", "--listen", "0.0.0.0"])
    check = find("couldn't determine")
    assert not check.ok
    assert "sudo ufw status verbose" in " ".join(check.hints)


def test_a_listen_address_that_has_vanished_is_flagged(firewall, host_addresses):
    runner.invoke(app, ["port", "set", "--listen", "172.17.0.1"])
    host_addresses.discard("172.17.0.1")
    assert not find("has no address 172.17.0.1 right now").ok


def test_wildcards_are_never_flagged_as_missing(firewall, host_addresses):
    runner.invoke(app, ["port", "set", "--listen", "0.0.0.0"])
    host_addresses.clear()
    assert not any("has no address" in m for m in messages())


def test_a_connected_engine_that_is_not_listening_is_flagged(monkeypatch, firewall):
    paths.run_dir().mkdir(parents=True, exist_ok=True)
    paths.pid_file().write_text(str(os.getpid()))
    paths.engine_meta_file().write_text('{"socks_port": 10808, "listen_address": "127.0.0.1"}')
    monkeypatch.setattr(supervisor, "_port_open", lambda port, host="127.0.0.1", timeout=0.3: False)
    assert not find("nothing is accepting connections on port 10808").ok


def test_the_output_indents_hints_under_their_warning(firewall):
    runner.invoke(app, ["port", "set", "--listen", "0.0.0.0"])
    output = runner.invoke(app, ["doctor"]).output
    lines = output.splitlines()
    index = next(i for i, line in enumerate(lines) if "No login is required" in line)
    assert lines[index].startswith("warn")
    assert UFW_ALLOW in lines[index + 2]
    assert lines[index + 1].startswith("       ")


# ---- doctor is what people run when something is wrong: it must report, not crash -------------------------


def test_a_corrupt_profile_store_is_reported_not_fatal(xray_installed):
    paths.profiles_file().parent.mkdir(parents=True, exist_ok=True)
    paths.profiles_file().write_text("{not json")
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0, result.output
    assert "Couldn't read the saved profiles" in result.output
    assert "Xray masque: supported" in result.output  # the rest of the report is still there


def test_a_corrupt_login_file_is_reported_not_fatal(firewall):
    runner.invoke(app, ["port", "set", "--listen", "0.0.0.0"])
    paths.auth_file().write_text("{broken")
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0, result.output
    assert "login file" in result.output and "unreadable" in result.output
    assert "No login is required" in result.output  # and the exposure advice still follows
