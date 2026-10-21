from __future__ import annotations

import os
import stat

import pytest
from typer.testing import CliRunner

from v2rm.cli.app import app
from v2rm.errors import V2rmError
from v2rm.models.auth import ProxyAuth
from v2rm.net.docker import DockerGateway
from v2rm.store import paths
from v2rm.store.auth import AuthStore
from v2rm.store.state import AppStateStore

runner = CliRunner()

UFW_ALLOW = "sudo ufw allow from 172.16.0.0/12 to any port 10808,10809 proto tcp"


def test_port_show_defaults():
    result = runner.invoke(app, ["port", "show"])
    assert result.exit_code == 0, result.output
    assert "10808" in result.output
    assert "10809" in result.output
    assert "127.0.0.1" in result.output
    assert "auth    none" in result.output
    assert "Warning" not in result.output


def test_port_set_updates_state():
    result = runner.invoke(app, ["port", "set", "--socks", "11000", "--http", "11001"])
    assert result.exit_code == 0, result.output

    shown = runner.invoke(app, ["port", "show"])
    assert "11000" in shown.output
    assert "11001" in shown.output


def test_port_set_rejects_same_port():
    result = runner.invoke(app, ["port", "set", "--socks", "12000", "--http", "12000"])
    assert result.exit_code != 0


def test_port_set_rejects_out_of_range():
    result = runner.invoke(app, ["port", "set", "--socks", "99999"])
    assert result.exit_code != 0


def test_port_set_with_nothing_is_a_noop():
    result = runner.invoke(app, ["port", "set"])
    assert result.exit_code == 0, result.output
    assert "Nothing to change" in result.output


# ---- --listen ---------------------------------------------------------------------------------


def test_port_set_listen_address_updates_state_and_warns():
    result = runner.invoke(app, ["port", "set", "--listen", "172.17.0.1"])
    assert result.exit_code == 0, result.output
    assert "Warning" in result.output  # non-loopback listen address must warn

    shown = runner.invoke(app, ["port", "show"])
    assert "172.17.0.1" in shown.output


def test_port_set_listen_0000_is_valid_and_warns():
    result = runner.invoke(app, ["port", "set", "--listen", "0.0.0.0"])
    assert result.exit_code == 0, result.output
    assert "Warning" in result.output
    assert AppStateStore().load().listen_address == "0.0.0.0"


def test_wildcards_pass_even_if_the_host_has_no_such_address(host_addresses):
    host_addresses.clear()
    assert runner.invoke(app, ["port", "set", "--listen", "0.0.0.0"]).exit_code == 0
    assert runner.invoke(app, ["port", "set", "--listen", "::"]).exit_code == 0


def test_port_set_listen_loopback_no_warning():
    assert runner.invoke(app, ["port", "set", "--listen", "172.17.0.1"]).exit_code == 0

    result = runner.invoke(app, ["port", "set", "--listen", "127.0.0.1"])
    assert result.exit_code == 0, result.output
    assert "Warning" not in result.output


def test_port_set_rejects_invalid_listen_address():
    result = runner.invoke(app, ["port", "set", "--listen", "not-an-ip"])
    assert result.exit_code != 0
    assert "valid IP address" in str(result.exception)


def test_port_set_rejects_an_address_the_host_does_not_have_and_changes_nothing():
    result = runner.invoke(app, ["port", "set", "--listen", "10.99.99.99", "--socks", "11000"])
    assert result.exit_code != 0
    assert "no address 10.99.99.99" in str(result.exception)
    state = AppStateStore().load()
    assert state.listen_address == "127.0.0.1" and state.socks_port == 10808  # nothing was saved


# ---- --listen docker ---------------------------------------------------------------------------


def test_listen_docker_resolves_the_bridge_address_and_says_what_it_found(monkeypatch):
    monkeypatch.setattr(
        "v2rm.cli.port.resolve_docker_gateway",
        lambda: DockerGateway("172.17.0.1", "`docker network inspect bridge`"),
    )
    result = runner.invoke(app, ["port", "set", "--listen", "docker"])
    assert result.exit_code == 0, result.output
    assert "Docker bridge address: 172.17.0.1" in result.output
    assert "docker network inspect bridge" in result.output
    assert "other networks" in result.output  # the note about compose networks
    assert AppStateStore().load().listen_address == "172.17.0.1"


def test_listen_docker_is_case_insensitive(monkeypatch):
    monkeypatch.setattr("v2rm.cli.port.resolve_docker_gateway", lambda: DockerGateway("172.17.0.1", "docker0"))
    assert runner.invoke(app, ["port", "set", "--listen", "Docker"]).exit_code == 0


def test_listen_docker_reports_a_failed_lookup(monkeypatch):
    def fail():
        raise V2rmError("Couldn't find the Docker bridge address: ...")

    monkeypatch.setattr("v2rm.cli.port.resolve_docker_gateway", fail)
    result = runner.invoke(app, ["port", "set", "--listen", "docker"])
    assert result.exit_code != 0
    assert "Couldn't find the Docker bridge address" in str(result.exception)
    assert AppStateStore().load().listen_address == "127.0.0.1"


def test_listen_docker_refuses_a_gateway_this_host_does_not_have(monkeypatch):
    # Rootless Docker / Docker Desktop report a bridge address that lives in a VM or namespace.
    monkeypatch.setattr("v2rm.cli.port.resolve_docker_gateway", lambda: DockerGateway("10.88.0.1", "docker"))
    result = runner.invoke(app, ["port", "set", "--listen", "docker"])
    assert result.exit_code != 0
    assert "10.88.0.1" in str(result.exception) and "no such address" in str(result.exception)


# ---- --auth / --no-auth ------------------------------------------------------------------------


def test_auth_is_stored_privately_and_never_echoed():
    result = runner.invoke(app, ["port", "set", "--auth", "demo:s3cret-pass"])
    assert result.exit_code == 0, result.output
    assert "s3cret-pass" not in result.output
    assert "login required" in result.output

    assert AuthStore().load().user == "demo"
    assert AuthStore().load().password == "s3cret-pass"
    assert "s3cret-pass" not in paths.state_file().read_text(encoding="utf-8")  # not in state.json
    if os.name == "posix":
        assert stat.S_IMODE(paths.auth_file().stat().st_mode) == 0o600

    shown = runner.invoke(app, ["port", "show"])
    assert "required (user: demo)" in shown.output
    assert "s3cret-pass" not in shown.output


def test_a_password_may_contain_colons():
    assert runner.invoke(app, ["port", "set", "--auth", "demo:a:b:c"]).exit_code == 0
    assert AuthStore().load().password == "a:b:c"


@pytest.mark.parametrize("value", ["nocolon", "user:", ":pass", "", "us\ner:pass", "user:pa\x00ss", "u:" + "x" * 256])
def test_bad_auth_values_are_rejected(value):
    result = runner.invoke(app, ["port", "set", "--auth", value])
    assert result.exit_code != 0
    assert AuthStore().load() is None


def test_no_auth_removes_the_login():
    runner.invoke(app, ["port", "set", "--auth", "demo:pw"])
    result = runner.invoke(app, ["port", "set", "--no-auth"])
    assert result.exit_code == 0, result.output
    assert AuthStore().load() is None
    assert not paths.auth_file().exists()
    assert "login not required" in result.output


def test_auth_and_no_auth_together_are_rejected():
    result = runner.invoke(app, ["port", "set", "--auth", "a:b", "--no-auth"])
    assert result.exit_code != 0
    assert "can't be used together" in str(result.exception)


# ---- --user / --password ------------------------------------------------------------------------------


def test_user_and_password_set_the_login_for_both_ports():
    result = runner.invoke(app, ["port", "set", "--user", "alice", "--password", "s3cret-pass"])
    assert result.exit_code == 0, result.output
    assert AuthStore().load() == ProxyAuth("alice", "s3cret-pass")
    assert "s3cret-pass" not in result.output
    assert "login required (user: alice)" in result.output
    assert "v2rm env" in result.output  # says where to get the URLs with the login filled in

    shown = runner.invoke(app, ["port", "show"])
    assert "auth    required (user: alice)" in shown.output
    assert "s3cret-pass" not in shown.output
    if os.name == "posix":
        assert stat.S_IMODE(paths.auth_file().stat().st_mode) == 0o600


def test_a_user_without_a_password_is_asked_for_it_at_a_hidden_prompt():
    result = runner.invoke(app, ["port", "set", "--user", "alice"], input="s3cret-pass\ns3cret-pass\n")
    assert result.exit_code == 0, result.output
    assert AuthStore().load() == ProxyAuth("alice", "s3cret-pass")
    assert "Password for alice" in result.output
    assert "s3cret-pass" not in result.output  # typed hidden, never echoed back


def test_the_prompt_asks_again_until_both_entries_match():
    result = runner.invoke(app, ["port", "set", "--user", "alice"], input="one\ntwo\nsame\nsame\n")
    assert result.exit_code == 0, result.output
    assert "do not match" in result.output
    assert AuthStore().load() == ProxyAuth("alice", "same")


def test_no_password_to_be_had_changes_nothing():
    runner.invoke(app, ["port", "set", "--auth", "old:pw"])
    result = runner.invoke(app, ["port", "set", "--user", "alice", "--socks", "11000"], input="")  # nothing to read
    assert result.exit_code != 0
    assert "No password was given" in str(result.exception) and "--password" in str(result.exception)
    assert AuthStore().load() == ProxyAuth("old", "pw")
    assert AppStateStore().load().socks_port == 10808  # the ports weren't touched either


def test_a_password_alone_replaces_the_password_of_the_current_login():
    runner.invoke(app, ["port", "set", "--auth", "alice:old-pass"])
    result = runner.invoke(app, ["port", "set", "--password", "new-pass"])
    assert result.exit_code == 0, result.output
    assert AuthStore().load() == ProxyAuth("alice", "new-pass")
    assert "new-pass" not in result.output


def test_a_password_alone_needs_a_login_to_belong_to():
    result = runner.invoke(app, ["port", "set", "--password", "pw"])
    assert result.exit_code != 0
    assert "--user" in str(result.exception)
    assert AuthStore().load() is None


def test_a_new_user_name_replaces_the_whole_login():
    runner.invoke(app, ["port", "set", "--auth", "alice:old-pass"])
    assert runner.invoke(app, ["port", "set", "--user", "bob", "--password", "bob-pass"]).exit_code == 0
    assert AuthStore().load() == ProxyAuth("bob", "bob-pass")


@pytest.mark.parametrize(
    "args",
    [
        ["--auth", "a:b", "--user", "c"],
        ["--auth", "a:b", "--password", "c"],
        ["--no-auth", "--auth", "a:b"],
        ["--no-auth", "--user", "alice"],
        ["--no-auth", "--password", "pw"],
    ],
)
def test_the_ways_of_naming_a_login_do_not_mix(args):
    result = runner.invoke(app, ["port", "set", *args])
    assert result.exit_code != 0
    assert "can't be used together" in str(result.exception)
    assert AuthStore().load() is None


@pytest.mark.parametrize(
    "args, message",
    [
        (["--user", "", "--password", "pw"], "user name can't be empty"),
        (["--user", "alice", "--password", ""], "password can't be empty"),
        (["--user", "al:ice", "--password", "pw"], "can't contain a colon"),
        (["--user", "al\nice", "--password", "pw"], "control characters"),
        (["--user", "alice", "--password", "p\x00w"], "control characters"),
        (["--user", "u" * 256, "--password", "pw"], "user name is too long"),
        (["--user", "alice", "--password", "p" * 256], "password is too long"),
    ],
)
def test_bad_user_names_and_passwords_are_rejected(args, message):
    result = runner.invoke(app, ["port", "set", *args])
    assert result.exit_code != 0
    assert message in str(result.exception)
    assert AuthStore().load() is None


def test_a_bad_user_name_is_refused_before_the_password_is_asked_for():
    result = runner.invoke(app, ["port", "set", "--user", "al:ice"])
    assert result.exit_code != 0 and "can't contain a colon" in str(result.exception)
    assert "Password for" not in result.output


def test_bad_ports_are_refused_before_the_password_is_asked_for():
    result = runner.invoke(app, ["port", "set", "--user", "alice", "--socks", "99999"])
    assert result.exit_code != 0 and "valid port number" in str(result.exception)
    assert "Password for" not in result.output


def test_a_user_name_with_markup_characters_is_printed_as_typed():
    result = runner.invoke(app, ["port", "set", "--user", "[bold]x[/bold]", "--password", "pw"])
    assert result.exit_code == 0, result.output
    assert "(user: [bold]x[/bold])" in result.output
    assert "(user: [bold]x[/bold])" in runner.invoke(app, ["port", "show"]).output


def test_the_login_is_kept_when_only_the_ports_change():
    runner.invoke(app, ["port", "set", "--user", "alice", "--password", "pw"])
    result = runner.invoke(app, ["port", "set", "--socks", "11000"])
    assert result.exit_code == 0, result.output
    assert "login required (user: alice)" in result.output
    assert AuthStore().load() == ProxyAuth("alice", "pw")


def test_no_auth_means_no_user_name_and_no_password():
    runner.invoke(app, ["port", "set", "--user", "alice", "--password", "pw"])
    result = runner.invoke(app, ["port", "set", "--no-auth"])
    assert result.exit_code == 0, result.output
    assert "login not required" in result.output
    assert AuthStore().load() is None
    shown = runner.invoke(app, ["port", "show"])
    assert "auth    none" in shown.output and "alice" not in shown.output


def test_port_show_says_how_to_set_a_login_when_there_is_none():
    assert "v2rm port set --user NAME" in runner.invoke(app, ["port", "show"]).output


def test_a_login_keeps_the_open_proxy_warning_away_like_auth_does():
    result = runner.invoke(app, ["port", "set", "--listen", "172.17.0.1", "--user", "alice", "--password", "pw"])
    assert result.exit_code == 0, result.output
    assert "no authentication" not in result.output and "ufw" not in result.output


def test_a_login_set_while_connected_reconnects(connected):
    result = runner.invoke(app, ["port", "set", "--user", "alice", "--password", "pw", "--yes"])
    assert result.exit_code == 0, result.output
    assert connected == [None]
    assert AuthStore().load() == ProxyAuth("alice", "pw")


def test_nothing_to_change_names_the_login_options():
    result = runner.invoke(app, ["port", "set"])
    assert "--user" in result.output and "--no-auth" in result.output


def test_moving_one_port_onto_the_other_one_is_refused():
    # --socks alone, onto the HTTP port that is already there.
    result = runner.invoke(app, ["port", "set", "--socks", "10809"])
    assert result.exit_code != 0
    assert "can't both be 10809" in str(result.exception)
    assert AppStateStore().load().socks_port == 10808


# ---- what the warnings say ------------------------------------------------------------------------


def test_open_proxy_warning_includes_the_firewall_commands_when_there_is_no_login():
    result = runner.invoke(app, ["port", "set", "--listen", "172.17.0.1"])
    assert "no authentication" in result.output
    assert UFW_ALLOW in result.output


def test_a_login_removes_the_open_proxy_warning_but_not_the_listen_warning():
    result = runner.invoke(app, ["port", "set", "--listen", "172.17.0.1", "--auth", "demo:pw"])
    assert result.exit_code == 0, result.output
    assert "Warning" in result.output and "not just localhost" in result.output
    assert "no authentication" not in result.output
    assert "ufw" not in result.output


def test_changing_only_the_port_still_warns_while_listening_beyond_localhost():
    runner.invoke(app, ["port", "set", "--listen", "0.0.0.0"])
    result = runner.invoke(app, ["port", "set", "--socks", "11000"])
    assert "Warning" in result.output
    assert "port 11000,10809 proto tcp" in result.output  # the commands follow the new port


def test_warning_commands_use_the_configured_ports():
    result = runner.invoke(app, ["port", "set", "--listen", "0.0.0.0", "--socks", "1080", "--http", "8080"])
    assert "port 1080,8080 proto tcp" in result.output


def test_port_show_warns_briefly():
    runner.invoke(app, ["port", "set", "--listen", "0.0.0.0"])
    shown = runner.invoke(app, ["port", "show"])
    assert "Warning" in shown.output
    assert "v2rm doctor" in shown.output
    assert UFW_ALLOW not in shown.output  # the full commands are for doctor


# ---- reconnecting -------------------------------------------------------------------------------------


@pytest.fixture
def connected(monkeypatch):
    calls = []
    monkeypatch.setattr("v2rm.process.supervisor.is_connected", lambda: (True, 4242))
    monkeypatch.setattr("v2rm.cli.connect.connect_command", lambda ref: calls.append(ref))
    return calls


def test_reconnects_when_connected_and_confirmed(connected):
    result = runner.invoke(app, ["port", "set", "--auth", "demo:pw", "--yes"])
    assert result.exit_code == 0, result.output
    assert connected == [None]  # `connect_command(None)`: reconnect the active profile


def test_declining_the_reconnect_still_saves_and_says_how_to_apply(connected):
    result = runner.invoke(app, ["port", "set", "--auth", "demo:pw"], input="n\n")
    assert result.exit_code == 0, result.output
    assert connected == []
    assert "Saved." in result.output and "v2rm connect" in result.output
    assert AuthStore().load() is not None


def test_the_exposure_warning_is_not_printed_twice_when_reconnecting(connected):
    # connect prints it itself (stubbed out here), so `port set` must not.
    result = runner.invoke(app, ["port", "set", "--listen", "0.0.0.0", "--yes"])
    assert "Warning" not in result.output
