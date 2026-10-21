from __future__ import annotations

import pytest
import requests
from typer.testing import CliRunner

from v2rm.cli.app import app
from v2rm.models.auth import ProxyAuth
from v2rm.store.auth import AuthStore
from v2rm.store.state import AppStateStore

runner = CliRunner()


class FakeResponse:
    def __init__(self, status_code: int = 200, text: str = ""):
        self.status_code = status_code
        self.text = text


def test_menu_status_then_quit():
    result = runner.invoke(app, ["menu"], input="3\n0\n")
    assert result.exit_code == 0, result.output
    assert "Not connected" in result.output


def test_menu_invalid_choice_then_quit():
    result = runner.invoke(app, ["menu"], input="99\n0\n")
    assert result.exit_code == 0, result.output
    assert "Not a valid choice" in result.output


def test_bare_invocation_launches_menu():
    result = runner.invoke(app, [], input="0\n")
    assert result.exit_code == 0, result.output
    assert "interactive menu" in result.output


def test_menu_add_link_flow():
    result = runner.invoke(
        app, ["menu"], input="5\ntrojan://pw@menu.example.com:443?security=tls#MenuAddedNode\n0\n"
    )
    assert result.exit_code == 0, result.output

    listed = runner.invoke(app, ["profile", "list"])
    assert "MenuAddedNode" in listed.output


def test_menu_list_profiles_flow():
    runner.invoke(app, ["add", "trojan://pw@ml.example.com:443?security=tls#ListedViaMenu"])
    result = runner.invoke(app, ["menu"], input="4\n0\n")
    assert result.exit_code == 0, result.output
    assert "ListedViaMenu" in result.output


def test_menu_connect_with_no_profiles():
    result = runner.invoke(app, ["menu"], input="1\n0\n")
    assert result.exit_code == 0, result.output
    assert "No profiles yet" in result.output


def test_menu_connect_flow_with_profile_reports_engine_not_installed():
    runner.invoke(app, ["add", "trojan://pw@mc.example.com:443?security=tls#ConnViaMenu"])
    result = runner.invoke(app, ["menu"], input="1\n1\n0\n")
    assert result.exit_code == 0, result.output
    assert "not installed" in result.output


def test_menu_disconnect_when_not_connected_shows_error_not_crash():
    result = runner.invoke(app, ["menu"], input="2\n0\n")
    assert result.exit_code == 0, result.output
    assert "Error" in result.output


def test_menu_remove_profile_flow():
    runner.invoke(app, ["add", "trojan://pw@rmv.example.com:443?security=tls#RemoveViaMenu"])
    # 9 = Remove a profile, pick #1, confirm "y" at remove_profile's own prompt.
    result = runner.invoke(app, ["menu"], input="9\n1\ny\n0\n")
    assert result.exit_code == 0, result.output

    listed = runner.invoke(app, ["profile", "list"])
    assert "RemoveViaMenu" not in listed.output


def test_menu_remove_profile_with_no_profiles():
    result = runner.invoke(app, ["menu"], input="9\n0\n")
    assert result.exit_code == 0, result.output
    assert "No profiles yet" in result.output


def test_menu_remove_subscription_flow(monkeypatch):
    monkeypatch.setattr(
        requests, "get", lambda *a, **k: FakeResponse(200, "trojan://pw@rms.example.com:443#RmSubMember")
    )
    runner.invoke(app, ["sub", "add", "https://example.com/menu-rm-sub", "--name", "MenuRmSub"])

    # 10 = Remove a subscription, pick #1, confirm "y".
    result = runner.invoke(app, ["menu"], input="10\n1\ny\n0\n")
    assert result.exit_code == 0, result.output

    listed = runner.invoke(app, ["profile", "list"])
    assert "RmSubMember" not in listed.output


def test_menu_remove_subscription_with_none():
    result = runner.invoke(app, ["menu"], input="10\n0\n")
    assert result.exit_code == 0, result.output
    assert "No subscriptions yet" in result.output


def test_menu_update_one_subscription_flow(monkeypatch):
    monkeypatch.setattr(
        requests, "get", lambda *a, **k: FakeResponse(200, "trojan://pw@u1.example.com:443#MenuUpdKeep")
    )
    runner.invoke(app, ["sub", "add", "https://example.com/menu-upd-sub", "--name", "MenuUpdSub"])

    monkeypatch.setattr(
        requests, "get", lambda *a, **k: FakeResponse(200, "trojan://pw@u2.example.com:443#MenuUpdNew")
    )
    # 13 = Update a subscription, pick #1.
    result = runner.invoke(app, ["menu"], input="13\n1\n0\n")
    assert result.exit_code == 0, result.output

    listed = runner.invoke(app, ["profile", "list"])
    assert "MenuUpdNew" in listed.output
    assert "MenuUpdKeep" not in listed.output


def test_menu_lists_the_new_add_entries():
    result = runner.invoke(app, ["menu"], input="0\n")
    assert "7) Add a JSON config" in result.output
    assert "8) Add a MASQUE server" in result.output


def test_menu_add_json_flow(tmp_path):
    from tests.helpers import FIXTURES

    result = runner.invoke(app, ["menu"], input=f"7\n{FIXTURES / 'serverless_subscription.json'}\n0\n")
    assert result.exit_code == 0, result.output
    listed = runner.invoke(app, ["profile", "list"]).output
    assert "Serverless-v52-fragA" in listed and "Serverless-v52-fragB" in listed


def test_menu_add_json_with_a_bad_path_reports_instead_of_crashing():
    result = runner.invoke(app, ["menu"], input="7\n/no/such/file.json\n0\n")
    assert result.exit_code == 0, result.output
    assert "File not found" in result.output


def test_menu_add_json_with_an_empty_answer_does_nothing():
    result = runner.invoke(app, ["menu"], input="7\n\n0\n")
    assert result.exit_code == 0, result.output


@pytest.mark.filterwarnings("ignore::getpass.GetPassWarning")  # no real terminal under CliRunner
def test_menu_add_masque_flow():
    # server, port, sni, alpn, user, password, path, name
    answers = "m.example.com\n8443\nfront.example.com\nh2\nalice\ns3cret\n/masque\nMenuMasque\n"
    result = runner.invoke(app, ["menu"], input=f"8\n{answers}0\n")
    assert result.exit_code == 0, result.output

    from v2rm.store.profiles import ProfileStore

    (p,) = ProfileStore().list()
    assert (p.name, p.server, p.port, p.tls.sni, p.tls.alpn) == ("MenuMasque", "m.example.com", 8443, "front.example.com", ["h2"])
    assert p.extra["user"] == "alice" and p.password == "s3cret" and p.transport.path == "/masque"
    assert "s3cret" not in result.output  # typed at a hidden prompt, never echoed back


def test_menu_add_masque_with_defaults():
    # server only; everything else Enter (SNI defaults to the server, port 443, h2, no login).
    result = runner.invoke(app, ["menu"], input="8\nm.example.com\n\n\n\n\n\n\n0\n")
    assert result.exit_code == 0, result.output

    from v2rm.store.profiles import ProfileStore

    (p,) = ProfileStore().list()
    assert (p.port, p.tls.sni, p.tls.alpn, p.password, p.name) == (443, "m.example.com", ["h2"], "", "m.example.com:443")


def test_menu_add_masque_reports_a_validation_error_without_crashing():
    # server, port, sni, alpn, (no user), path "not-a-path", (no name)
    result = runner.invoke(app, ["menu"], input="8\nm.example.com\n443\ns\nh2\n\nnot-a-path\n\n0\n")
    assert result.exit_code == 0, result.output
    assert 'must start with "/"' in result.output


def test_menu_profile_picker_shows_types_and_literal_names():
    runner.invoke(app, ["add", "trojan://pw@t.example.com:443#[free] node"])
    result = runner.invoke(app, ["menu"], input="1\n0\n0\n")
    assert "[free] node" in result.output and "(trojan, t.example.com:443)" in result.output


# ---- local proxy settings (17) ---------------------------------------------------------------------------
# Answers, in order: Login (keep/set/none), [user name], SOCKS port, HTTP port, listen address,
# and, for "set", the password twice. Enter keeps the offered value.


def test_menu_lists_the_local_proxy_settings():
    result = runner.invoke(app, ["menu"], input="0\n")
    assert "17) Local proxy" in result.output


def test_menu_shows_the_current_settings_first():
    result = runner.invoke(app, ["menu"], input="17\nkeep\n\n\n\n0\n")
    assert result.exit_code == 0, result.output
    assert "socks   127.0.0.1:10808" in result.output and "auth    none" in result.output
    assert "Nothing changed" in result.output


def test_menu_sets_a_user_name_and_password():
    result = runner.invoke(app, ["menu"], input="17\nset\nalice\n\n\n\npw-1\npw-1\n0\n")
    assert result.exit_code == 0, result.output
    assert AuthStore().load() == ProxyAuth("alice", "pw-1")
    assert "login required (user: alice)" in result.output
    assert "pw-1" not in result.output
    assert AppStateStore().load().socks_port == 10808  # Enter kept the ports


def test_menu_removes_the_login():
    AuthStore().save(ProxyAuth("alice", "pw"))
    result = runner.invoke(app, ["menu"], input="17\nnone\n\n\n\n0\n")
    assert result.exit_code == 0, result.output
    assert "login not required" in result.output
    assert AuthStore().load() is None


def test_menu_changes_the_ports_and_keeps_the_login():
    AuthStore().save(ProxyAuth("alice", "pw"))
    result = runner.invoke(app, ["menu"], input="17\nkeep\n11000\n11001\n\n0\n")
    assert result.exit_code == 0, result.output
    state = AppStateStore().load()
    assert (state.socks_port, state.http_port) == (11000, 11001)
    assert AuthStore().load() == ProxyAuth("alice", "pw")


def test_menu_changes_the_listen_address():
    result = runner.invoke(app, ["menu"], input="17\nkeep\n\n\n0.0.0.0\n0\n")
    assert result.exit_code == 0, result.output
    assert AppStateStore().load().listen_address == "0.0.0.0"
    assert "Warning" in result.output  # reachable beyond localhost, no login


def test_menu_needs_a_user_name_to_set_a_login():
    result = runner.invoke(app, ["menu"], input="17\nset\n\n0\n")
    assert result.exit_code == 0, result.output
    assert "A user name is needed" in result.output
    assert AuthStore().load() is None


def test_menu_reports_a_bad_user_name_without_asking_for_a_password():
    result = runner.invoke(app, ["menu"], input="17\nset\na:b\n\n\n\n0\n")
    assert result.exit_code == 0, result.output
    assert "can't contain a colon" in result.output
    assert "Password for" not in result.output
    assert AuthStore().load() is None


def test_menu_reports_a_bad_port_and_saves_nothing():
    result = runner.invoke(app, ["menu"], input="17\nset\nalice\n99999\n\n\n0\n")
    assert result.exit_code == 0, result.output
    assert "valid port number" in result.output
    assert AuthStore().load() is None
    assert AppStateStore().load().socks_port == 10808


def test_menu_refuses_one_port_for_both():
    result = runner.invoke(app, ["menu"], input="17\nkeep\n10809\n\n\n0\n")
    assert result.exit_code == 0, result.output
    assert "can't both be 10809" in result.output
    assert AppStateStore().load().socks_port == 10808


def test_menu_asks_the_login_question_again_after_a_wrong_answer():
    result = runner.invoke(app, ["menu"], input="17\nmaybe\nnone\n\n\n\n0\n")
    assert result.exit_code == 0, result.output
    assert "Please select one of the available options" in result.output
