from __future__ import annotations

import json
import os
import shlex
import sys
import textwrap

import pytest
from typer.testing import CliRunner

from tests.helpers import FIXTURES, load_json_fixture
from v2rm.cli.app import app
from v2rm.store.profiles import ProfileStore

runner = CliRunner()

SERVERLESS = FIXTURES / "serverless_subscription.json"


@pytest.fixture
def raw_profiles():
    """The two real serverless configs, added the way a user would."""
    assert runner.invoke(app, ["add", "--json", str(SERVERLESS)]).exit_code == 0
    return ProfileStore().list()


@pytest.fixture
def editor(tmp_path, monkeypatch):
    """Install a fake $EDITOR running the given Python snippet; the file to edit is `path`."""

    def install(body: str) -> None:
        script = tmp_path / "fake_editor.py"
        script.write_text("import json, os, sys\npath = sys.argv[1]\n" + textwrap.dedent(body), encoding="utf-8")
        if os.name == "nt":  # v2rm splits $EDITOR non-POSIX-style on Windows, where quotes would stay literal
            monkeypatch.setenv("EDITOR", f"{sys.executable} {script}")
        else:
            monkeypatch.setenv("EDITOR", f"{shlex.quote(sys.executable)} {shlex.quote(str(script))}")

    return install


# ---- list -------------------------------------------------------------------------------------------------


def test_the_list_has_a_type_column_with_a_dash_for_the_server_of_a_raw_config(raw_profiles):
    runner.invoke(app, ["add", "trojan://pw@t.example.com:443#Trojan1"])
    runner.invoke(app, ["add", "vless://11111111-2222-3333-4444-555555555555@v.example.com:443?security=tls#Vless1"])
    runner.invoke(app, ["add", "masque://m.example.com:443?sni=s#Masque1"])
    output = runner.invoke(app, ["profile", "list"]).output
    header = next(line for line in output.splitlines() if "Name" in line)
    assert "Type" in header and "Protocol" not in header

    rows = {name: next(line for line in output.splitlines() if name in line) for name in ("Serverless-v52-fragA", "Trojan1", "Vless1", "Masque1")}
    assert " raw " in rows["Serverless-v52-fragA"] and "—" in rows["Serverless-v52-fragA"]
    assert " trojan " in rows["Trojan1"] and "t.example.com:443" in rows["Trojan1"]
    assert " vless " in rows["Vless1"]
    assert " masque " in rows["Masque1"] and "m.example.com:443" in rows["Masque1"]


def test_the_list_can_be_filtered_by_the_type_names_it_shows(raw_profiles):
    runner.invoke(app, ["add", "trojan://pw@t.example.com:443#Trojan1"])
    for wanted, expected in (("raw", 2), ("raw-xray", 2), ("trojan", 1), ("RAW", 2)):
        output = runner.invoke(app, ["profile", "list", "--protocol", wanted]).output
        names = [n for n in ("Serverless-v52-fragA", "Serverless-v52-fragB", "Trojan1") if n in output]
        assert len(names) == expected, (wanted, output)


def test_bracketed_names_are_not_swallowed_by_markup():
    runner.invoke(app, ["add", "trojan://pw@t.example.com:443#[free] node [vip1]"])
    assert "[free] node [vip1]" in runner.invoke(app, ["profile", "list"]).output


# ---- show -------------------------------------------------------------------------------------------------


def test_show_summarises_a_raw_config(raw_profiles):
    output = runner.invoke(app, ["profile", "show", "Serverless-v52-fragA"]).output
    assert "type       raw" in output
    assert "server     —" in output
    assert "outbounds  7:" in output and "tcp-fragment (direct)" in output
    assert "inbounds   1 (mixed)" in output and "replaced by v2rm's own SOCKS/HTTP" in output
    assert "route presets are not applied" in output
    assert "needs      Xray-core >= 26.6.27" in output
    assert "not a tunnel" in output  # serverless


def test_show_json_prints_the_config_itself_and_it_can_be_added_again(raw_profiles):
    result = runner.invoke(app, ["profile", "show", "Serverless-v52-fragA", "--json"])
    assert result.exit_code == 0, result.output
    config = json.loads(result.stdout)
    assert config == load_json_fixture("serverless_subscription.json")[0]

    runner.invoke(app, ["profile", "remove", "Serverless-v52-fragB", "--yes"])
    again = runner.invoke(app, ["add", "--json", "-"], input=result.stdout)
    assert again.exit_code == 0, again.output
    assert [p.raw_config for p in ProfileStore().list()].count(config) == 2


def test_show_link_for_a_raw_profile_explains_there_is_none_and_points_at_json(raw_profiles):
    result = runner.invoke(app, ["profile", "show", "Serverless-v52-fragA", "--link"])
    assert result.exit_code != 0
    message = str(result.exception)
    assert "no share link" in message and "profile show <id> --json" in message


def test_show_link_and_json_together_are_rejected(raw_profiles):
    result = runner.invoke(app, ["profile", "show", "Serverless-v52-fragA", "--link", "--json"])
    assert result.exit_code != 0


def test_show_json_for_an_ordinary_profile_is_its_stored_data():
    runner.invoke(app, ["add", "trojan://pw@t.example.com:443#T"])
    data = json.loads(runner.invoke(app, ["profile", "show", "T", "--json"]).stdout)
    assert data["server"] == "t.example.com" and data["protocol"] == "trojan"


def test_show_masque_hides_the_password_and_header_values():
    runner.invoke(
        app,
        ["add", "masque", "--server", "m.example.com", "--sni", "s", "--user", "alice", "--pass", "topsecret",
         "--path", "/p", "--header", "X-Token: abc123", "--name", "M"],
    )
    output = runner.invoke(app, ["profile", "show", "M"]).output
    assert "masque" in output and "alice" in output and "/p" in output and "X-Token" in output
    assert "topsecret" not in output and "abc123" not in output


def test_show_a_real_link_profile_lists_the_extended_options():
    from tests.helpers import free_links

    runner.invoke(app, ["add", free_links()[0]])
    profile = ProfileStore().list()[0]
    output = runner.invoke(app, ["profile", "show", profile.id]).output
    assert "fingerprint unsafe" in output
    assert "finalmask  fragment, fragment" in output
    assert "ciphers" in output and "TLS_AES_256_GCM_SHA384" in output


# ---- edit: raw JSON ---------------------------------------------------------------------------------------------


def test_editing_a_raw_profile_opens_its_json_and_saves_the_change(raw_profiles, editor):
    editor(
        """
        config = json.load(open(path, encoding="utf-8"))
        config["remarks"] = "Renamed-by-edit"
        config["log"] = {"loglevel": "debug"}
        json.dump(config, open(path, "w", encoding="utf-8"))
        """
    )
    result = runner.invoke(app, ["profile", "edit", "Serverless-v52-fragA"])
    assert result.exit_code == 0, result.output
    edited = next(p for p in ProfileStore().list() if p.name == "Renamed-by-edit")
    assert edited.raw_config["log"] == {"loglevel": "debug"}
    assert edited.raw_config["outbounds"] == load_json_fixture("serverless_subscription.json")[0]["outbounds"]
    assert len(ProfileStore().list()) == 2


def test_the_editor_is_shown_the_pretty_printed_config(raw_profiles, editor, tmp_path):
    seen = tmp_path / "seen.txt"
    editor(f'open({str(seen)!r}, "w", encoding="utf-8").write(open(path, encoding="utf-8").read())')
    runner.invoke(app, ["profile", "edit", "Serverless-v52-fragA"])
    text = seen.read_text(encoding="utf-8")
    assert text.startswith("{\n  ") and json.loads(text) == load_json_fixture("serverless_subscription.json")[0]


def test_an_unchanged_edit_keeps_everything_as_it_was(raw_profiles, editor):
    editor("pass")
    before = ProfileStore().list()
    assert runner.invoke(app, ["profile", "edit", "Serverless-v52-fragA"]).exit_code == 0
    assert [(p.name, p.raw_config) for p in ProfileStore().list()] == [(p.name, p.raw_config) for p in before]


def test_the_name_is_kept_when_remarks_did_not_change(raw_profiles, editor):
    runner.invoke(app, ["profile", "rename", "Serverless-v52-fragA", "My own name"])
    editor(
        """
        config = json.load(open(path, encoding="utf-8"))
        config["log"] = {"loglevel": "none"}
        json.dump(config, open(path, "w", encoding="utf-8"))
        """
    )
    runner.invoke(app, ["profile", "edit", "My own name"])
    assert "My own name" in [p.name for p in ProfileStore().list()]


def test_invalid_json_is_reported_and_declining_leaves_the_profile_alone(raw_profiles, editor):
    editor('open(path, "w", encoding="utf-8").write("{ nope")')
    before = [p.raw_config for p in ProfileStore().list()]
    result = runner.invoke(app, ["profile", "edit", "Serverless-v52-fragA"], input="n\n")
    assert result.exit_code != 0
    assert "Not saved: Not valid JSON" in result.output
    assert "Edit abandoned" in str(result.exception)
    assert [p.raw_config for p in ProfileStore().list()] == before


def test_a_config_without_an_outbounds_list_is_refused(raw_profiles, editor):
    editor('open(path, "w", encoding="utf-8").write(\'{"remarks": "x"}\')')
    result = runner.invoke(app, ["profile", "edit", "Serverless-v52-fragA"], input="n\n")
    assert "no 'outbounds' list" in result.output
    assert result.exit_code != 0


def test_after_a_mistake_the_editor_reopens_on_what_was_typed(raw_profiles, editor, tmp_path):
    counter = tmp_path / "runs.txt"
    editor(
        f"""
        runs = {str(counter)!r}
        first = not os.path.exists(runs)
        open(runs, "a").write("x")
        if first:
            open(path, "w", encoding="utf-8").write('{{"remarks": "typo",,}}')
        else:
            assert open(path, encoding="utf-8").read() == '{{"remarks": "typo",,}}', "the user's text was lost"
            open(path, "w", encoding="utf-8").write('{{"remarks": "Fixed", "outbounds": []}}')
        """
    )
    result = runner.invoke(app, ["profile", "edit", "Serverless-v52-fragA"], input="y\n")
    assert result.exit_code == 0, result.output
    assert counter.read_text() == "xx"
    assert "Fixed" in [p.name for p in ProfileStore().list()]


def test_flags_that_make_no_sense_for_a_raw_config_are_refused(raw_profiles):
    for flag in (["--server", "x"], ["--port", "1"], ["--uuid", "u"], ["--password", "p"], ["--sni", "s"]):
        result = runner.invoke(app, ["profile", "edit", "Serverless-v52-fragA", *flag])
        assert result.exit_code != 0
        assert "complete config" in str(result.exception)
        assert "profile edit Serverless-v52-fragA" in str(result.exception)


def test_renaming_a_raw_config_with_the_name_flag_is_fine(raw_profiles):
    assert runner.invoke(app, ["profile", "edit", "Serverless-v52-fragA", "--name", "Short"]).exit_code == 0
    assert "Short" in [p.name for p in ProfileStore().list()]


# ---- edit: other kinds ----------------------------------------------------------------------------------------------


def test_masque_flag_edits_are_validated_before_saving():
    runner.invoke(app, ["add", "masque", "--server", "m.example.com", "--sni", "s", "--name", "M"])
    assert runner.invoke(app, ["profile", "edit", "M", "--sni", "other.example.com"]).exit_code == 0
    assert ProfileStore().list()[0].tls.sni == "other.example.com"

    result = runner.invoke(app, ["profile", "edit", "M", "--server", ""])
    assert result.exit_code != 0
    assert "needs a server" in str(result.exception)
    assert ProfileStore().list()[0].server == "m.example.com"


def test_ordinary_profiles_still_edit_through_a_yaml_dump(editor):
    runner.invoke(app, ["add", "trojan://pw@t.example.com:443#Old"])
    editor(
        """
        text = open(path, encoding="utf-8").read().replace("name: Old", "name: New")
        open(path, "w", encoding="utf-8").write(text)
        """
    )
    assert runner.invoke(app, ["profile", "edit", "Old"]).exit_code == 0
    assert [p.name for p in ProfileStore().list()] == ["New"]
