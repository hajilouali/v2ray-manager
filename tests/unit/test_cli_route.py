from __future__ import annotations

import requests
from typer.testing import CliRunner

from v2rm.cli.app import app
from v2rm.store import paths

runner = CliRunner()


def test_route_show_global_default():
    result = runner.invoke(app, ["route", "show"])
    assert result.exit_code == 0, result.output
    assert "global" in result.output


def test_route_set_bypass_ir_and_show():
    result = runner.invoke(app, ["route", "set", "bypass-ir"])
    assert result.exit_code == 0, result.output

    shown = runner.invoke(app, ["route", "show"])
    assert "bypass-ir" in shown.output
    assert "direct" in shown.output


def test_route_set_custom_scaffolds_file():
    result = runner.invoke(app, ["route", "set", "custom"])
    assert result.exit_code == 0, result.output
    assert paths.custom_routes_file().exists()


def test_route_set_rejects_unknown_preset():
    result = runner.invoke(app, ["route", "set", "not-a-real-preset"])
    assert result.exit_code != 0


def test_route_update_data(monkeypatch):
    class FakeResponse:
        status_code = 200
        content = b"DATA"

    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse())
    result = runner.invoke(app, ["route", "update-data"])
    assert result.exit_code == 0, result.output
    assert "Updated" in result.output
