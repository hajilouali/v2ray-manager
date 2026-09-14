from __future__ import annotations

from typer.testing import CliRunner

from v2rm.cli.app import app

runner = CliRunner()


def test_menu_status_then_quit():
    result = runner.invoke(app, ["menu"], input="9\n0\n")
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
        app, ["menu"], input="3\ntrojan://pw@menu.example.com:443?security=tls#MenuAddedNode\n0\n"
    )
    assert result.exit_code == 0, result.output

    listed = runner.invoke(app, ["profile", "list"])
    assert "MenuAddedNode" in listed.output


def test_menu_list_profiles_flow():
    runner.invoke(app, ["add", "trojan://pw@ml.example.com:443?security=tls#ListedViaMenu"])
    result = runner.invoke(app, ["menu"], input="6\n0\n")
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
