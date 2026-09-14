from __future__ import annotations

from typer.testing import CliRunner

from v2rm.cli.app import app

runner = CliRunner()


def test_add_and_list_profile():
    link = "trojan://pw@host.example.com:443?security=tls#CliNode"
    result = runner.invoke(app, ["add", link])
    assert result.exit_code == 0, result.output
    assert "CliNode" in result.output

    result = runner.invoke(app, ["profile", "list"])
    assert result.exit_code == 0, result.output
    assert "CliNode" in result.output


def test_add_invalid_link_reports_error_line():
    result = runner.invoke(app, ["add", "bogus://nope"])
    assert "bogus://nope" in result.output
    assert result.exit_code != 0


def test_add_multiple_links_via_stdin():
    links = "\n".join(
        [
            "trojan://pw@a.example.com:443#First",
            "trojan://pw@b.example.com:443#Second",
        ]
    )
    result = runner.invoke(app, ["add", "-"], input=links)
    assert result.exit_code == 0, result.output
    assert "First" in result.output
    assert "Second" in result.output

    listed = runner.invoke(app, ["profile", "list"])
    assert "First" in listed.output
    assert "Second" in listed.output


def test_profile_rename_and_remove():
    link = "trojan://pw@rm.example.com:443#ToRemove"
    runner.invoke(app, ["add", link])

    renamed = runner.invoke(app, ["profile", "rename", "ToRemove", "Renamed"])
    assert renamed.exit_code == 0, renamed.output

    listed = runner.invoke(app, ["profile", "list"])
    assert "Renamed" in listed.output
    assert "ToRemove" not in listed.output

    removed = runner.invoke(app, ["profile", "remove", "Renamed", "--yes"])
    assert removed.exit_code == 0, removed.output

    listed2 = runner.invoke(app, ["profile", "list"])
    assert "Renamed" not in listed2.output


def test_profile_show_link_round_trip():
    link = (
        "vless://11111111-2222-3333-4444-555555555555@r.example.com:443"
        "?security=reality&sni=hide.example.com&pbk=pub&sid=ab#RNode"
    )
    runner.invoke(app, ["add", link])

    show = runner.invoke(app, ["profile", "show", "RNode", "--link"])
    assert show.exit_code == 0, show.output
    assert show.output.strip().startswith("vless://")


def test_profile_edit_flag_and_use():
    link = "trojan://pw@edit.example.com:443#EditMe"
    runner.invoke(app, ["add", link])

    edited = runner.invoke(app, ["profile", "edit", "EditMe", "--server", "new.example.com"])
    assert edited.exit_code == 0, edited.output

    show = runner.invoke(app, ["profile", "show", "EditMe"])
    assert "new.example.com" in show.output

    used = runner.invoke(app, ["profile", "use", "EditMe"])
    assert used.exit_code == 0, used.output
    assert "Active profile set to" in used.output

    listed = runner.invoke(app, ["profile", "list"])
    assert "*" in listed.output
