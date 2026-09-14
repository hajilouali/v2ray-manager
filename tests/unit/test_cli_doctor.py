from __future__ import annotations

from typer.testing import CliRunner

from v2rm.cli.app import app

runner = CliRunner()


def test_doctor_runs_and_reports_checks():
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0, result.output
    assert "xray" in result.output
    assert "singbox" in result.output
    assert "Not connected" in result.output
