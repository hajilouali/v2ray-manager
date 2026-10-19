from __future__ import annotations

import json
import os
import sys

from typer.testing import CliRunner

from v2rm.cli.app import app
from v2rm.net.docker import DockerGateway
from v2rm.store import paths

runner = CliRunner()


def test_env_requires_connection():
    result = runner.invoke(app, ["env"])
    assert result.exit_code != 0


def test_exec_requires_connection():
    result = runner.invoke(app, ["exec", "--", "echo", "hi"])
    assert result.exit_code != 0


def _fake_connect(socks_port: int = 10808, http_port: int = 10809) -> None:
    paths.run_dir().mkdir(parents=True, exist_ok=True)
    paths.pid_file().write_text(str(os.getpid()))
    paths.engine_meta_file().write_text(
        json.dumps(
            {"engine": "xray", "profile_name": "Demo", "socks_port": socks_port, "http_port": http_port}
        )
    )


def test_env_prints_export_statements():
    _fake_connect()
    result = runner.invoke(app, ["env"])
    assert result.exit_code == 0, result.output
    assert "export http_proxy=http://127.0.0.1:10809" in result.output
    assert "export all_proxy=socks5h://127.0.0.1:10808" in result.output
    assert "export no_proxy=" in result.output


def test_env_fish_shell_syntax():
    _fake_connect()
    result = runner.invoke(app, ["env", "--shell", "fish"])
    assert result.exit_code == 0, result.output
    assert "set -gx http_proxy" in result.output


def test_exec_runs_command_with_proxy_env(tmp_path):
    _fake_connect(socks_port=11080, http_port=11081)
    marker = tmp_path / "out.txt"

    result = runner.invoke(
        app,
        [
            "exec",
            "--",
            sys.executable,
            "-c",
            f"import os; open(r'{marker}', 'w').write(os.environ.get('all_proxy', ''))",
        ],
    )
    assert result.exit_code == 0, result.output
    assert marker.read_text() == "socks5h://127.0.0.1:11080"


# ---- the address and login a client really needs --------------------------------------------------------


def _fake_running(listen_address="127.0.0.1", authenticated=False, socks_port=10808, http_port=10809):
    paths.run_dir().mkdir(parents=True, exist_ok=True)
    paths.pid_file().write_text(str(os.getpid()))
    paths.engine_meta_file().write_text(
        json.dumps(
            {
                "engine": "xray", "profile_name": "Demo", "listen_address": listen_address,
                "authenticated": authenticated, "socks_port": socks_port, "http_port": http_port,
            }
        )
    )


def _lines(result):
    return result.stdout.splitlines()


def test_env_uses_the_address_the_proxy_is_bound_to():
    _fake_running(listen_address="172.17.0.1")
    result = runner.invoke(app, ["env"])
    assert "export http_proxy=http://172.17.0.1:10809" in _lines(result)
    assert "export all_proxy=socks5h://172.17.0.1:10808" in _lines(result)
    assert "export no_proxy=localhost,127.0.0.1,::1,172.17.0.1" in _lines(result)  # the proxy's own host is never proxied


def test_env_uses_loopback_for_a_wildcard_listen_address():
    _fake_running(listen_address="0.0.0.0")
    assert "export http_proxy=http://127.0.0.1:10809" in _lines(runner.invoke(app, ["env"]))


def test_env_brackets_an_ipv6_address():
    _fake_running(listen_address="fd00::1")
    assert "export http_proxy=http://[fd00::1]:10809" in _lines(runner.invoke(app, ["env"]))


def test_env_embeds_the_login_percent_encoded():
    runner.invoke(app, ["port", "set", "--auth", "us er:p@ss/w:rd"])
    _fake_running(authenticated=True)
    lines = _lines(runner.invoke(app, ["env"]))
    assert "export http_proxy=http://us%20er:p%40ss%2Fw%3Ard@127.0.0.1:10809" in lines
    assert "export all_proxy=socks5h://us%20er:p%40ss%2Fw%3Ard@127.0.0.1:10808" in lines


def test_env_leaves_the_login_out_when_the_running_proxy_has_none():
    # `port set --auth` was run but the proxy hasn't been reconnected: the
    # running one still accepts anyone, so a login in the URL would be wrong.
    runner.invoke(app, ["port", "set", "--auth", "demo:pw"])
    _fake_running(authenticated=False)
    assert "export http_proxy=http://127.0.0.1:10809" in _lines(runner.invoke(app, ["env"]))


def test_env_fish_syntax_carries_the_login_too():
    runner.invoke(app, ["port", "set", "--auth", "demo:pw"])
    _fake_running(authenticated=True)
    assert "set -gx http_proxy http://demo:pw@127.0.0.1:10809" in _lines(runner.invoke(app, ["env", "--shell", "fish"]))


def test_long_lines_are_never_wrapped():
    # `eval "$(v2rm env)"` breaks if a long line is wrapped at the terminal width.
    runner.invoke(app, ["port", "set", "--auth", "u" * 100 + ":" + "p" * 200])
    _fake_running(authenticated=True)
    lines = _lines(runner.invoke(app, ["env"]))
    long_line = f"export http_proxy=http://{'u' * 100}:{'p' * 200}@127.0.0.1:10809"
    assert len(long_line) > 200
    assert long_line in lines


def test_exec_passes_the_login_to_the_command(tmp_path):
    runner.invoke(app, ["port", "set", "--auth", "demo:pw"])
    _fake_running(authenticated=True, socks_port=11080, http_port=11081)
    marker = tmp_path / "out.txt"
    result = runner.invoke(
        app,
        ["exec", "--", sys.executable, "-c", f"import os; open(r'{marker}', 'w').write(os.environ['HTTP_PROXY'])"],
    )
    assert result.exit_code == 0, result.output
    assert marker.read_text() == "http://demo:pw@127.0.0.1:11081"


# ---- env --host / --docker: a block for a container ------------------------------------------------------


def test_host_prints_a_container_env_block_without_needing_a_connection():
    result = runner.invoke(app, ["env", "--host", "host.docker.internal"])
    assert result.exit_code == 0, result.output
    lines = _lines(result)
    assert "HTTP_PROXY=http://host.docker.internal:10809" in lines
    assert "HTTPS_PROXY=http://host.docker.internal:10809" in lines
    assert "ALL_PROXY=socks5h://host.docker.internal:10808" in lines
    assert "http_proxy=http://host.docker.internal:10809" in lines
    assert "NO_PROXY=localhost,127.0.0.1,::1,host.docker.internal" in lines
    assert not any(line.startswith("export ") for line in lines)


def test_the_block_explains_how_to_make_the_name_resolve():
    text = runner.invoke(app, ["env", "--host", "host.docker.internal"]).stdout
    assert "--add-host=host.docker.internal:host-gateway" in text
    assert 'extra_hosts: ["host.docker.internal:host-gateway"]' in text
    assert all(line.startswith("#") or "=" in line for line in text.splitlines())  # a valid env file


def test_the_block_follows_the_configured_ports_and_login():
    runner.invoke(app, ["port", "set", "--socks", "1080", "--http", "8080", "--listen", "0.0.0.0", "--auth", "demo:pw"])
    result = runner.invoke(app, ["env", "--host", "172.17.0.1"])
    lines = _lines(result)
    assert "HTTP_PROXY=http://demo:pw@172.17.0.1:8080" in lines
    assert "ALL_PROXY=socks5h://demo:pw@172.17.0.1:1080" in lines
    assert "keep the file private" in result.stdout


def test_docker_uses_the_bridge_address(monkeypatch):
    monkeypatch.setattr("v2rm.cli.env.resolve_docker_gateway", lambda: DockerGateway("172.17.0.1", "docker0"))
    runner.invoke(app, ["port", "set", "--listen", "172.17.0.1"])
    result = runner.invoke(app, ["env", "--docker"])
    assert result.exit_code == 0, result.output
    assert "HTTP_PROXY=http://172.17.0.1:10809" in _lines(result)
    assert "NO_PROXY=localhost,127.0.0.1,::1,172.17.0.1" in _lines(result)
    assert "Docker bridge address: 172.17.0.1" in result.stderr
    assert "Warning" not in result.output


def test_a_block_for_a_proxy_that_listens_on_loopback_warns_on_stderr_only():
    result = runner.invoke(app, ["env", "--host", "172.17.0.1"])
    assert "Warning: v2rm listens on 127.0.0.1, which containers can't reach" in result.stderr
    assert "v2rm port set --listen docker" in result.stderr
    assert "Warning" not in result.stdout  # the block stays clean for `> proxy.env`


def test_a_block_pointing_somewhere_other_than_the_bound_address_warns():
    runner.invoke(app, ["port", "set", "--listen", "192.168.1.5"])
    result = runner.invoke(app, ["env", "--host", "172.17.0.1"])
    assert "listens on 192.168.1.5, not on 172.17.0.1" in result.stderr


def test_a_wildcard_listen_needs_no_warning():
    runner.invoke(app, ["port", "set", "--listen", "0.0.0.0"])
    assert "Warning" not in runner.invoke(app, ["env", "--host", "172.17.0.1"]).stderr


def test_a_host_name_cannot_be_checked_so_only_loopback_is_warned_about():
    runner.invoke(app, ["port", "set", "--listen", "172.17.0.1"])
    assert "Warning" not in runner.invoke(app, ["env", "--host", "host.docker.internal"]).stderr


def test_host_and_docker_together_are_rejected():
    result = runner.invoke(app, ["env", "--host", "x", "--docker"])
    assert result.exit_code != 0
    assert "either --host or --docker" in str(result.exception)


def test_an_empty_host_is_rejected():
    assert runner.invoke(app, ["env", "--host", " "]).exit_code != 0
