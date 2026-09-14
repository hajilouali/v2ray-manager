from __future__ import annotations

from typer.testing import CliRunner

from v2rm.cli.app import app

runner = CliRunner()


def test_port_show_defaults():
    result = runner.invoke(app, ["port", "show"])
    assert result.exit_code == 0, result.output
    assert "10808" in result.output
    assert "10809" in result.output


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
