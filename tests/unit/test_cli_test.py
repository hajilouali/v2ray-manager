from __future__ import annotations

from typer.testing import CliRunner

from v2rm.cli.app import app

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
