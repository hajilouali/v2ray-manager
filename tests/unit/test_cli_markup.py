"""Names, URLs and error text come from subscriptions and share links, so they
can contain anything -- including `[free]` or `[vip1]`, which rich would
otherwise read as style tags and swallow. Every place that prints them must
show them literally."""

from __future__ import annotations

import requests
from typer.testing import CliRunner

from v2rm.cli.app import app

runner = CliRunner()

NAME = "[free] node [vip1]"
SUB_NAME = "[sale] sub [x]"


class FakeResponse:
    def __init__(self, status_code: int = 200, text: str = ""):
        self.status_code = status_code
        self.text = text
        self.headers: dict = {}


def serve(monkeypatch, body: str) -> None:
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(200, body))


def test_subscription_commands_print_names_literally(monkeypatch):
    serve(monkeypatch, f"trojan://pw@t.example.com:443#{NAME}")
    added = runner.invoke(app, ["sub", "add", "https://example.com/s", "--name", SUB_NAME])
    assert added.exit_code == 0, added.output
    assert SUB_NAME in added.output

    assert SUB_NAME in runner.invoke(app, ["sub", "list"]).output
    shown = runner.invoke(app, ["sub", "show", SUB_NAME]).output
    assert SUB_NAME in shown and NAME in shown

    updated = runner.invoke(app, ["sub", "update", SUB_NAME])
    assert f"Updating {SUB_NAME}" in updated.output

    removed = runner.invoke(app, ["sub", "remove", SUB_NAME, "--yes"])
    assert f"Removed {SUB_NAME}" in removed.output


def test_a_failed_update_shows_the_error_text_literally(monkeypatch):
    serve(monkeypatch, "trojan://pw@t.example.com:443#x")
    runner.invoke(app, ["sub", "add", "https://example.com/s", "--name", "S"])

    def boom(*args, **kwargs):
        raise requests.ConnectionError("could not reach [host] now")

    monkeypatch.setattr(requests, "get", boom)
    output = runner.invoke(app, ["sub", "update", "S"]).output
    assert "could not reach [host] now" in output
    assert "could not reach [host] now" in runner.invoke(app, ["sub", "list"]).output


def test_unparseable_entries_are_echoed_literally(monkeypatch):
    serve(monkeypatch, "trojan://pw@t.example.com:443#ok\nvless://[bad]-entry\n")
    output = runner.invoke(app, ["sub", "add", "https://example.com/s", "--name", "S"]).output
    assert "vless://[bad]-entry" in output


def test_profile_commands_print_names_literally():
    runner.invoke(app, ["add", f"trojan://pw@t.example.com:443#{NAME}"])
    assert NAME in runner.invoke(app, ["profile", "list"]).output
    assert NAME in runner.invoke(app, ["profile", "show", NAME]).output
    renamed = runner.invoke(app, ["profile", "rename", NAME, "[new] name"])
    assert "Renamed to [new] name" in renamed.output
    assert "[new] name" in runner.invoke(app, ["profile", "list"]).output
    used = runner.invoke(app, ["profile", "use", "[new] name"])
    assert "[new] name" in used.output
    removed = runner.invoke(app, ["profile", "remove", "[new] name", "--yes", "--force"])
    assert "Removed [new] name" in removed.output


def test_error_messages_keep_their_brackets():
    result = runner.invoke(app, ["profile", "show", "[nothing] here"])
    assert result.exit_code != 0
    assert "[nothing] here" in str(result.exception)
