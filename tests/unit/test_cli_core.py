from __future__ import annotations

from typer.testing import CliRunner

from v2rm.cli.app import app
from v2rm.coredl import install as installer

runner = CliRunner()


def test_core_list_shows_none_when_nothing_installed():
    result = runner.invoke(app, ["core", "list"])
    assert result.exit_code == 0, result.output
    assert "xray" in result.output
    assert "singbox" in result.output
    assert "none" in result.output


def test_core_use_sets_active_engine():
    result = runner.invoke(app, ["core", "use", "xray"])
    assert result.exit_code == 0, result.output
    assert "xray" in result.output

    listed = runner.invoke(app, ["core", "list"])
    assert listed.exit_code == 0, listed.output


def test_core_use_rejects_unknown_engine():
    result = runner.invoke(app, ["core", "use", "not-a-real-engine"])
    assert result.exit_code != 0


def test_core_list_reflects_installed_version():
    installer._install_binary("xray", "v1.2.3", b"fake")
    installer.use_version("xray", "v1.2.3")

    result = runner.invoke(app, ["core", "list"])
    assert "v1.2.3" in result.output


def test_core_remove_requires_version_or_all():
    result = runner.invoke(app, ["core", "remove", "xray"])
    assert result.exit_code != 0


def test_version_command_runs():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0, result.output
    assert "v2rm" in result.output
