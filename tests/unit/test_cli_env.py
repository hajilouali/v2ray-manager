from __future__ import annotations

import json
import os
import sys

from typer.testing import CliRunner

from v2rm.cli.app import app
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
