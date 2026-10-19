from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from tests.helpers import FIXTURES, load_json_fixture
from v2rm.cli.app import app
from v2rm.models.enums import Protocol
from v2rm.store.profiles import ProfileStore

runner = CliRunner()

SERVERLESS = FIXTURES / "serverless_subscription.json"
FREE_CONFIGS = FIXTURES / "free_configs_sample.txt"


def profiles():
    return ProfileStore().list()


# ---- the existing forms keep working ----------------------------------------------------------------


def test_add_a_link():
    result = runner.invoke(app, ["add", "trojan://pw@t.example.com:443?security=tls#Plain"])
    assert result.exit_code == 0, result.output
    assert "Plain" in result.output and "(trojan, t.example.com:443" in result.output
    assert [p.name for p in profiles()] == ["Plain"]


def test_add_with_the_explicit_link_subcommand():
    result = runner.invoke(app, ["add", "link", "trojan://pw@t.example.com:443#Explicit"])
    assert result.exit_code == 0, result.output
    assert [p.name for p in profiles()] == ["Explicit"]


def test_add_links_from_stdin():
    stdin = "trojan://pw@a.example.com:443#A\ntrojan://pw@b.example.com:443#B\n"
    result = runner.invoke(app, ["add", "-"], input=stdin)
    assert result.exit_code == 0, result.output
    assert [p.name for p in profiles()] == ["A", "B"]


def test_add_links_from_a_file_with_the_short_option(tmp_path):
    path = tmp_path / "links.txt"
    path.write_text("trojan://pw@a.example.com:443#FromFile\n", encoding="utf-8")
    assert runner.invoke(app, ["add", "-f", str(path)]).exit_code == 0
    assert runner.invoke(app, ["add", "--file", str(path)]).exit_code == 0
    assert [p.name for p in profiles()] == ["FromFile", "FromFile"]


def test_a_bare_add_explains_itself_and_fails():
    result = runner.invoke(app, ["add"])
    assert result.exit_code == 1
    assert "Provide a link" in result.output and "v2rm add masque" in result.output


def test_a_bad_link_is_reported_with_its_text_and_fails():
    result = runner.invoke(app, ["add", "bogus://nope"])
    assert result.exit_code != 0
    assert "bogus://nope" in result.output


def test_a_real_sample_file_of_many_links_is_added_in_one_go():
    result = runner.invoke(app, ["add", "-f", str(FREE_CONFIGS)])
    assert result.exit_code == 0, result.output
    added = profiles()
    assert len(added) == 12
    assert {p.protocol for p in added} == {Protocol.VLESS, Protocol.TROJAN}
    listed = runner.invoke(app, ["profile", "list"]).output
    assert "vless" in listed and "trojan" in listed


def test_the_group_help_lists_both_subcommands_and_the_shortcuts():
    result = runner.invoke(app, ["add", "--help"])
    assert result.exit_code == 0, result.output
    assert "link" in result.output and "masque" in result.output
    assert "--json" in result.output


def test_the_link_form_help_shows_its_options():
    result = runner.invoke(app, ["add", "link", "--help"])
    assert "--json" in result.output and "--file" in result.output


# ---- Xray JSON ---------------------------------------------------------------------------------------------


def test_add_json_file_with_an_array_of_configs():
    result = runner.invoke(app, ["add", "--json", str(SERVERLESS)])
    assert result.exit_code == 0, result.output
    added = profiles()
    assert [p.name for p in added] == ["Serverless-v52-fragA", "Serverless-v52-fragB"]
    assert all(p.protocol == Protocol.RAW_XRAY and p.is_raw for p in added)
    assert "(raw, —, id " in result.output
    assert added[0].raw_config == load_json_fixture("serverless_subscription.json")[0]  # stored verbatim


def test_add_json_from_stdin_with_a_single_object():
    config = {"remarks": "One", "outbounds": [{"protocol": "freedom", "tag": "direct"}]}
    result = runner.invoke(app, ["add", "--json", "-"], input=json.dumps(config))
    assert result.exit_code == 0, result.output
    (only,) = profiles()
    assert only.name == "One" and only.raw_config == config


def test_a_config_without_remarks_gets_a_stable_generated_name():
    config = {"outbounds": [{"protocol": "freedom"}]}
    runner.invoke(app, ["add", "--json", "-"], input=json.dumps(config))
    (only,) = profiles()
    assert only.name.startswith("raw-xray-") and len(only.name) == len("raw-xray-") + 8


def test_not_json_is_an_error_and_adds_nothing(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{ nope", encoding="utf-8")
    result = runner.invoke(app, ["add", "--json", str(path)])
    assert result.exit_code != 0
    assert "Not valid JSON" in str(result.exception)
    assert profiles() == []


def test_json_without_an_outbounds_list_is_an_error(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text('{"remarks": "x", "inbounds": []}', encoding="utf-8")
    result = runner.invoke(app, ["add", "--json", str(path)])
    assert result.exit_code == 1
    assert "no 'outbounds' list" in result.output
    assert profiles() == []


def test_one_bad_item_in_an_array_does_not_stop_the_others(tmp_path):
    path = tmp_path / "mixed.json"
    path.write_text(json.dumps([{"remarks": "good", "outbounds": []}, {"remarks": "bad"}, 5]), encoding="utf-8")
    result = runner.invoke(app, ["add", "--json", str(path)])
    assert result.exit_code == 0, result.output
    assert [p.name for p in profiles()] == ["good"]
    assert "bad" in result.output and "no 'outbounds' list" in result.output


def test_json_cannot_be_combined_with_a_link_or_file():
    result = runner.invoke(app, ["add", "--json", "x.json", "trojan://pw@t.example.com:443"])
    assert result.exit_code != 0
    assert "can't be combined" in str(result.exception)


def test_a_missing_json_file_is_reported():
    result = runner.invoke(app, ["add", "--json", "/no/such/file.json"])
    assert result.exit_code != 0
    assert "File not found" in str(result.exception)


def test_a_json_config_given_as_plain_input_is_recognised():
    result = runner.invoke(app, ["add", "-f", str(SERVERLESS)])
    assert result.exit_code == 0, result.output
    assert "adding it as one" in result.output
    assert len(profiles()) == 2 and all(p.is_raw for p in profiles())


def test_a_json_config_piped_without_the_flag_is_recognised_too():
    result = runner.invoke(app, ["add", "-"], input=SERVERLESS.read_text(encoding="utf-8"))
    assert result.exit_code == 0, result.output
    assert len(profiles()) == 2


# ---- MASQUE ---------------------------------------------------------------------------------------------------


def test_masque_with_just_the_required_options():
    result = runner.invoke(app, ["add", "masque", "--server", "m.example.com", "--sni", "front.example.com"])
    assert result.exit_code == 0, result.output
    (p,) = profiles()
    assert p.protocol == Protocol.MASQUE
    assert (p.server, p.port, p.tls.sni, p.tls.alpn) == ("m.example.com", 443, "front.example.com", ["h2"])
    assert p.name == "m.example.com:443"
    assert "(masque, m.example.com:443" in result.output

    link = runner.invoke(app, ["profile", "show", "m.example.com:443", "--link"]).stdout.strip()
    assert link == "masque://m.example.com:443?sni=front.example.com&alpn=h2#m.example.com%3A443"


def test_masque_with_every_option():
    result = runner.invoke(
        app,
        [
            "add", "masque", "--server", "m.example.com", "--port", "8443", "--sni", "front.example.com",
            "--alpn", "h2", "--user", "alice", "--pass", "s3cret", "--path", "/masque",
            "--host", "h.example.com", "--header", "X-A: 1", "--header", "X-B: two: parts",
            "--fp", "chrome", "--name", "MyMasque",
        ],
    )
    assert result.exit_code == 0, result.output
    (p,) = profiles()
    assert p.name == "MyMasque" and p.port == 8443
    assert p.extra["user"] == "alice" and p.password == "s3cret"
    assert (p.transport.path, p.transport.host) == ("/masque", "h.example.com")
    assert p.transport.headers == {"X-A": "1", "X-B": "two: parts"}  # split at the first colon only
    assert p.tls.fingerprint == "chrome"
    assert "s3cret" not in result.output

    # What was stored survives a round trip through the share link.
    from v2rm.parsers import parse_link

    again = parse_link(p.raw_link)
    assert again.extra == p.extra and again.password == p.password and again.transport.headers == p.transport.headers


def test_masque_alpn_h3_and_several():
    runner.invoke(app, ["add", "masque", "--server", "a.example.com", "--sni", "s", "--alpn", "h3", "--name", "A"])
    runner.invoke(app, ["add", "masque", "--server", "b.example.com", "--sni", "s", "--alpn", "h2, h3", "--name", "B"])
    by_name = {p.name: p for p in profiles()}
    assert by_name["A"].tls.alpn == ["h3"]
    assert by_name["B"].tls.alpn == ["h2", "h3"]


@pytest.mark.parametrize(
    ("extra_args", "message"),
    [
        (["--user", "alice"], "--user and --pass go together"),
        (["--pass", "secret"], "--user and --pass go together"),
        (["--path", "masque"], 'must start with "/"'),
        (["--header", "Host: x.example.com"], 'can\'t contain "Host"'),
        (["--header", "Capsule-Protocol: ?1"], "Capsule-Protocol"),
        (["--header", "no-colon-here"], "--header must look like"),
        (["--user", "a:b", "--pass", "p"], 'can\'t contain ":"'),
        (["--header", "Authorization: Bearer x", "--user", "a", "--pass", "p"], "Authorization"),
        (["--port", "0"], "invalid port"),
        (["--port", "70000"], "invalid port"),
    ],
)
def test_masque_validation_errors_are_clear_and_nothing_is_stored(extra_args, message):
    result = runner.invoke(app, ["add", "masque", "--server", "m.example.com", "--sni", "s", *extra_args])
    assert result.exit_code != 0
    assert message in str(result.exception)
    assert profiles() == []


def test_masque_requires_a_server_and_an_sni():
    assert runner.invoke(app, ["add", "masque", "--sni", "s"]).exit_code == 2
    assert runner.invoke(app, ["add", "masque", "--server", "m.example.com"]).exit_code == 2


def test_masque_help_lists_its_options():
    result = runner.invoke(app, ["add", "masque", "--help"])
    for option in ("--server", "--port", "--sni", "--alpn", "--user", "--pass", "--path", "--host", "--header", "--fp", "--name"):
        assert option in result.output


def test_a_masque_link_can_be_added_like_any_other():
    result = runner.invoke(app, ["add", "masque://alice:pw@m.example.com:443?sni=s.example.com#ViaLink"])
    assert result.exit_code == 0, result.output
    (p,) = profiles()
    assert p.protocol == Protocol.MASQUE and p.name == "ViaLink"


def test_bracketed_names_are_printed_literally():
    result = runner.invoke(app, ["add", "trojan://pw@t.example.com:443#[free] node"])
    assert "[free] node" in result.output
