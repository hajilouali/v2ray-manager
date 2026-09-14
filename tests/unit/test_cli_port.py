from __future__ import annotations

from typer.testing import CliRunner

from v2rm.cli.app import app

runner = CliRunner()


def test_port_show_defaults():
    result = runner.invoke(app, ["port", "show"])
    assert result.exit_code == 0, result.output
    assert "10808" in result.output
    assert "10809" in result.output
    assert "127.0.0.1" in result.output


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


def test_port_set_listen_address_updates_state():
    result = runner.invoke(app, ["port", "set", "--listen", "172.17.0.1"])
    assert result.exit_code == 0, result.output
    assert "Warning" in result.output  # non-loopback listen address must warn

    shown = runner.invoke(app, ["port", "show"])
    assert "172.17.0.1" in shown.output


def test_port_set_listen_0000_no_warning_suppressed_but_valid():
    result = runner.invoke(app, ["port", "set", "--listen", "0.0.0.0"])
    assert result.exit_code == 0, result.output
    assert "Warning" in result.output


def test_port_set_listen_loopback_no_warning():
    result = runner.invoke(app, ["port", "set", "--listen", "172.17.0.1"])
    assert result.exit_code == 0, result.output

    result2 = runner.invoke(app, ["port", "set", "--listen", "127.0.0.1"])
    assert result2.exit_code == 0, result2.output
    assert "Warning" not in result2.output


def test_port_set_rejects_invalid_listen_address():
    result = runner.invoke(app, ["port", "set", "--listen", "not-an-ip"])
    assert result.exit_code != 0
