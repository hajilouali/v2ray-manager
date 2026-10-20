from __future__ import annotations

import pytest
from typer.testing import CliRunner

from v2rm.cli.app import app
from v2rm.errors import V2rmError
from v2rm.models.aether import AetherSettings
from v2rm.models.enums import Protocol
from v2rm.models.profile import Profile
from v2rm.store import paths
from v2rm.store.profiles import ProfileStore

runner = CliRunner()


def add_aether(name="WARP") -> Profile:
    return ProfileStore().add(Profile(name=name, protocol=Protocol.AETHER, aether=AetherSettings()))


def add_trojan(name="trojan") -> Profile:
    return ProfileStore().add(
        Profile(name=name, protocol=Protocol.TROJAN, server=f"{name}.example.com", port=443, password="pw")
    )


def chain_profile(name):
    return next(p for p in ProfileStore().list() if p.name == name)


def make(*args):
    return runner.invoke(app, ["chain", "add", *args])


# ---- chain add -------------------------------------------------------------------------------------


def test_a_chain_is_made_from_profiles_in_traffic_order():
    warp, server = add_aether(), add_trojan()
    result = make("warp-then-trojan", "WARP", "trojan")
    assert result.exit_code == 0, result.output

    chain = chain_profile("warp-then-trojan")
    assert chain.is_chain
    assert [(h.kind, h.ref, h.name) for h in chain.chain] == [("profile", warp.id, "WARP"), ("profile", server.id, "trojan")]
    assert "v2rm connect warp-then-trojan" in result.output
    assert "WARP -> trojan" in result.output


def test_hops_can_be_named_by_id_or_unambiguous_id_prefix():
    warp, server = add_aether(), add_trojan()
    assert make("c", warp.id, server.id[:6]).exit_code == 0
    assert [h.ref for h in chain_profile("c").chain] == [warp.id, server.id]


def test_a_proxy_already_running_may_be_the_first_hop():
    add_trojan()
    result = make("via-local", "socks5://user:secret@127.0.0.1:1080", "trojan")
    assert result.exit_code == 0, result.output
    hop = chain_profile("via-local").chain[0]
    assert hop.kind == "proxy" and hop.ref == "socks5://user:secret@127.0.0.1:1080"
    assert "secret" not in result.output  # the password is never printed


def test_the_chain_becomes_a_profile_everything_else_can_use():
    add_aether(), add_trojan()
    make("c", "WARP", "trojan")
    listed = runner.invoke(app, ["profile", "list"])
    assert "c" in listed.output and "chain" in listed.output and "WARP -> trojan" in listed.output
    assert runner.invoke(app, ["profile", "rename", "c", "renamed"]).exit_code == 0
    assert runner.invoke(app, ["profile", "use", "renamed"]).exit_code == 0


def test_mistakes_are_explained_and_nothing_is_stored():
    add_aether(), add_trojan("one"), add_trojan("two")
    cases = [
        (["solo", "WARP"], "at least two hops"),
        (["c", "WARP", "missing"], "No profile found"),
        (["c", "trojan-x", "WARP"], "No profile found"),
        (["c", "one", "socks5://127.0.0.1:1080", "two"], "only be the first hop"),
        (["c", "WARP", "one", "WARP"], "appears twice"),
        (["c", "ftp://x:21", "one"], "neither a saved profile nor a proxy"),
        (["c", "socks5://127.0.0.1", "one"], "no port"),
        (["c", "https://proxy.example:8443", "one"], "plain HTTP"),
        (["c", "socks5://127.0.0.1:1080", "socks5://127.0.0.1:1081"], "no connection"),
    ]
    for args, fragment in cases:
        result = make(*args)
        assert result.exit_code != 0, (args, result.output)
        assert fragment in str(result.exception), (args, str(result.exception))
    assert not any(p.is_chain for p in ProfileStore().list())


def test_a_chain_cannot_reuse_the_name_of_a_profile():
    add_aether(), add_trojan()
    result = make("trojan", "WARP", "trojan")
    assert result.exit_code != 0 and "already exists" in str(result.exception)


# ---- list / show / remove ---------------------------------------------------------------------------


def test_list_shows_chains_and_whether_they_can_run():
    add_aether()
    add_trojan("gone")
    add_trojan("kept")
    make("fine", "WARP", "kept")
    make("broken", "WARP", "gone")
    ProfileStore().remove(next(p for p in ProfileStore().list() if p.name == "gone").id)

    result = runner.invoke(app, ["chain", "list"])
    assert result.exit_code == 0, result.output
    assert "fine" in result.output and "yes" in result.output
    assert "broken" in result.output and "no longer exists" in result.output


def test_list_with_no_chains_says_how_to_make_one():
    result = runner.invoke(app, ["chain", "list"])
    assert result.exit_code == 0 and "v2rm chain add" in result.output


def test_show_describes_hops_programs_and_notes():
    add_aether(), add_trojan()
    make("c", "WARP", "trojan")
    result = runner.invoke(app, ["chain", "show", "c"])
    assert result.exit_code == 0, result.output
    out = result.output
    assert "1. WARP" in out and "2. trojan" in out
    assert "closest to you" in out and "what the internet sees" in out
    assert "you -> WARP -> trojan -> the internet" in out
    assert "(aether)" in out and "(xray)" in out  # the programs, in start order
    assert "registers a free anonymous Cloudflare WARP device" in out
    assert out.count("registers a") == 1  # said once, not again as a generic tip


def test_show_a_broken_chain_names_the_missing_hop():
    add_aether(), add_trojan("gone")
    make("c", "WARP", "gone")
    ProfileStore().remove(next(p for p in ProfileStore().list() if p.name == "gone").id)
    result = runner.invoke(app, ["chain", "show", "c"])
    assert result.exit_code == 0
    assert "gone -- no longer exists" in result.output and "can't run" in result.output


def test_show_refuses_a_plain_profile():
    add_trojan()
    result = runner.invoke(app, ["chain", "show", "trojan"])
    assert result.exit_code != 0 and "not a chain" in str(result.exception)


def test_remove_deletes_the_chain_and_keeps_its_profiles():
    add_aether(), add_trojan()
    make("c", "WARP", "trojan")
    result = runner.invoke(app, ["chain", "remove", "c", "--yes"])
    assert result.exit_code == 0, result.output
    assert [p.name for p in ProfileStore().list()] == ["WARP", "trojan"]
    assert runner.invoke(app, ["chain", "remove", "trojan", "--yes"]).exit_code != 0


# ---- profiles that chains use --------------------------------------------------------------------------


def test_a_profile_that_is_a_hop_cannot_be_removed_without_force():
    add_aether(), add_trojan()
    make("c", "WARP", "trojan")
    result = runner.invoke(app, ["profile", "remove", "trojan", "--yes"])
    assert result.exit_code != 0
    assert "hop of the chain" in str(result.exception) and "'c'" in str(result.exception)
    assert any(p.name == "trojan" for p in ProfileStore().list())

    forced = runner.invoke(app, ["profile", "remove", "trojan", "--yes", "--force"])
    assert forced.exit_code == 0 and "now broken" in forced.output


def test_removing_an_aether_profile_deletes_its_identity():
    warp = add_aether()
    directory = paths.aether_profile_dir(warp.id)
    directory.mkdir(parents=True)
    (directory / "aether-masque.toml").write_text("keys")
    result = runner.invoke(app, ["profile", "remove", "WARP", "--yes"])
    assert result.exit_code == 0, result.output
    assert not directory.exists()
    assert "WARP identity" in result.output


# ---- profile show / edit ----------------------------------------------------------------------------------


def test_profile_show_of_an_aether_profile_lists_what_matters():
    profile = ProfileStore().add(
        Profile(
            name="W",
            protocol=Protocol.AETHER,
            aether=AetherSettings(
                transport="h2", fragment=True, noize="gfw", route_block=["ads.example"], upstream="socks5://u:pw@127.0.0.1:1080",
                env={"AETHER_ACCESS_CLIENT_SECRET": "topsecret"},
            ),
        )
    )
    result = runner.invoke(app, ["profile", "show", profile.id])
    out = result.output
    assert result.exit_code == 0, out
    assert "HTTP/2 (TCP)" in out and "found by scanning" in out and "gfw" in out and "fragment" in out
    assert "block" in out and "ads.example" in out
    assert "socks5://u:***@127.0.0.1:1080" in out and "pw@" not in out
    assert "AETHER_ACCESS_CLIENT_SECRET" in out and "topsecret" not in out  # names only
    assert "0/1 registered" in out


def test_profile_show_of_a_chain_lists_its_hops():
    add_aether(), add_trojan()
    make("c", "WARP", "trojan")
    result = runner.invoke(app, ["profile", "show", "c"])
    assert result.exit_code == 0, result.output
    assert "hop 1" in result.output and "hop 2" in result.output
    assert "you -> WARP -> trojan -> the internet" in result.output


def test_profile_show_json_round_trips_an_aether_profile():
    import json

    profile = add_aether()
    result = runner.invoke(app, ["profile", "show", profile.id, "--json"])
    data = json.loads(result.output)
    assert data["protocol"] == "aether" and data["aether"]["mode"] == "masque"


def test_edit_flags_do_not_apply_to_aether_profiles_or_chains():
    add_aether(), add_trojan()
    make("c", "WARP", "trojan")
    for ref in ("WARP", "c"):
        result = runner.invoke(app, ["profile", "edit", ref, "--server", "x.example.com"])
        assert result.exit_code != 0 and "no server, port or credentials" in str(result.exception)
    assert runner.invoke(app, ["profile", "edit", "WARP", "--name", "Renamed"]).exit_code == 0


def test_a_hand_edit_that_breaks_an_aether_profile_is_not_saved():
    from v2rm.cli.profile import _validate_edited
    from v2rm.models.aether import AetherMode

    profile = add_aether()
    profile.aether.transport = "h2"
    profile.aether.mode = AetherMode.WG
    with pytest.raises(V2rmError, match="Not saved.*UDP all the way"):
        _validate_edited(profile)


def test_a_hand_edit_that_breaks_a_chain_is_not_saved():
    from v2rm.cli.profile import _validate_edited

    add_aether(), add_trojan()
    make("c", "WARP", "trojan")
    chain = chain_profile("c")
    chain.chain.reverse()
    chain.chain.append(chain.chain[1])  # the same Aether profile twice
    with pytest.raises(V2rmError, match="Not saved.*appears twice"):
        _validate_edited(chain)


# ---- the menu --------------------------------------------------------------------------------------


def test_the_menu_can_make_a_chain():
    add_aether(), add_trojan()
    answers = ["16", "1 2", "menu chain", "0"]
    result = runner.invoke(app, ["menu"], input="\n".join(answers) + "\n")
    assert result.exit_code == 0, result.output
    chain = chain_profile("menu chain")
    assert [h.name for h in chain.chain] == ["WARP", "trojan"]


def test_the_menu_needs_two_profiles_for_a_chain():
    add_trojan()
    result = runner.invoke(app, ["menu"], input="16\n0\n")
    assert result.exit_code == 0 and "at least two saved profiles" in result.output
