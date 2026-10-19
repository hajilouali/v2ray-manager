from __future__ import annotations

from typer.testing import CliRunner

from tests.helpers import FIXTURES
from v2rm.cli.app import app

runner = CliRunner()

NOTE = "route presets are not applied to raw configs"


def use_raw():
    runner.invoke(app, ["add", "--json", str(FIXTURES / "serverless_subscription.json")])
    assert runner.invoke(app, ["profile", "use", "Serverless-v52-fragA"]).exit_code == 0


def test_route_show_says_presets_do_not_apply_when_the_active_profile_is_raw():
    use_raw()
    result = runner.invoke(app, ["route", "show"])
    assert result.exit_code == 0, result.output
    assert NOTE in result.output
    assert "global" in result.output  # still shows the preset itself


def test_route_show_has_no_such_note_for_ordinary_profiles():
    runner.invoke(app, ["add", "trojan://pw@t.example.com:443#T"])
    runner.invoke(app, ["profile", "use", "T"])
    assert NOTE not in runner.invoke(app, ["route", "show"]).output


def test_route_show_has_no_such_note_without_an_active_profile():
    assert NOTE not in runner.invoke(app, ["route", "show"]).output


def test_previewing_a_preset_still_carries_the_note():
    use_raw()
    assert NOTE in runner.invoke(app, ["route", "show", "--preset", "bypass-ir"]).output


def test_route_set_warns_that_the_new_preset_will_not_affect_a_raw_profile():
    use_raw()
    result = runner.invoke(app, ["route", "set", "bypass-ir"])
    assert result.exit_code == 0, result.output
    assert "Route preset set to" in result.output and NOTE in result.output


def test_switching_the_active_profile_away_from_raw_removes_the_note():
    use_raw()
    runner.invoke(app, ["add", "trojan://pw@t.example.com:443#T"])
    runner.invoke(app, ["profile", "use", "T"])
    assert NOTE not in runner.invoke(app, ["route", "show"]).output
