from __future__ import annotations

import requests
from typer.testing import CliRunner

from v2rm.cli.app import app

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
    # 7 = Remove a profile, pick #1, confirm "y" at remove_profile's own prompt.
    result = runner.invoke(app, ["menu"], input="7\n1\ny\n0\n")
    assert result.exit_code == 0, result.output

    listed = runner.invoke(app, ["profile", "list"])
    assert "RemoveViaMenu" not in listed.output


def test_menu_remove_profile_with_no_profiles():
    result = runner.invoke(app, ["menu"], input="7\n0\n")
    assert result.exit_code == 0, result.output
    assert "No profiles yet" in result.output


def test_menu_remove_subscription_flow(monkeypatch):
    monkeypatch.setattr(
        requests, "get", lambda *a, **k: FakeResponse(200, "trojan://pw@rms.example.com:443#RmSubMember")
    )
    runner.invoke(app, ["sub", "add", "https://example.com/menu-rm-sub", "--name", "MenuRmSub"])

    # 8 = Remove a subscription, pick #1, confirm "y".
    result = runner.invoke(app, ["menu"], input="8\n1\ny\n0\n")
    assert result.exit_code == 0, result.output

    listed = runner.invoke(app, ["profile", "list"])
    assert "RmSubMember" not in listed.output


def test_menu_remove_subscription_with_none():
    result = runner.invoke(app, ["menu"], input="8\n0\n")
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
    # 11 = Update a subscription, pick #1.
    result = runner.invoke(app, ["menu"], input="11\n1\n0\n")
    assert result.exit_code == 0, result.output

    listed = runner.invoke(app, ["profile", "list"])
    assert "MenuUpdNew" in listed.output
    assert "MenuUpdKeep" not in listed.output
