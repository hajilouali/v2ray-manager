"""The aether:// link: v2rm's own convention for passing an Aether setup around."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from v2rm.cli.app import app
from v2rm.errors import ParseError
from v2rm.models.aether import AetherMode, AetherSettings
from v2rm.models.enums import Protocol
from v2rm.models.profile import Profile
from v2rm.parsers import parse_link, parse_links, to_link
from v2rm.parsers.aether import link_omissions
from v2rm.parsers.aether import parse as parse_aether
from v2rm.store.profiles import ProfileStore

runner = CliRunner()


def profile(name="WARP h2", **settings) -> Profile:
    return Profile(name=name, protocol=Protocol.AETHER, aether=AetherSettings(**settings))


def test_the_default_profile_is_just_its_mode_and_name():
    assert to_link(profile("plain")) == "aether://masque#plain"


def test_only_what_differs_from_the_defaults_is_written():
    link = to_link(profile(transport="h2", fragment=True, fragment_size="8-16", noize="gfw"))
    assert link.startswith("aether://masque?")
    for part in ("transport=h2", "fragment=1", "fragment_size=8-16", "noize=gfw"):
        assert part in link
    assert "scan=" not in link and "quick_reconnect" not in link
    assert link.endswith("#WARP%20h2")


def test_a_rich_profile_round_trips_through_its_link():
    original = profile(
        mode=AetherMode.GOOL_CLASSIC,
        outer="162.159.192.1:2408",
        inner="188.114.96.1:2408",
        scan="verified",
        ip="both",
        noize="gfw",
        sni="www.cloudflare.com",
        ech="auto",
        quick_reconnect=False,
        reconnect_secs=3,
        keepalive=7,
        dns=["1.1.1.1", "9.9.9.9"],
        upstream="socks5://127.0.0.1:1080",
        route_block=["ads.example", "keyword:tracker"],
        route_direct=["private", "port:25", "10.0.0.0/8", "ip:2001:db8::/32"],
        route_sniff=False,
        route_sniff_ms=800,
        wait_secs=300,
        exit_loc="!IR,RU",
        mark="0xff",
        stats=True,
        disable_grease=True,
        quic_v2=False,
    )
    # gool-classic has no carrier or QUIC v2: drop what that mode refuses before comparing
    original.aether.quic_v2 = True
    link = to_link(original)
    again = parse_link(link)
    assert again.aether == original.aether
    assert again.name == "WARP h2" and again.raw_link == link and again.protocol == Protocol.AETHER


def test_a_regexp_rule_with_special_characters_survives():
    original = profile(route_block=["regexp:^ad[0-9]+"])
    assert parse_link(to_link(original)).aether.route_block == ["regexp:^ad[0-9]+"]


def test_a_non_ascii_name_survives():
    original = profile("واریرز WARP")
    assert parse_link(to_link(original)).name == "واریرز WARP"


def test_secrets_are_never_written_and_the_omission_is_reported():
    original = profile(upstream="socks5://alice:hunter2@127.0.0.1:1080", env={"AETHER_ACCESS_CLIENT_SECRET": "topsecret"})
    link = to_link(original)
    assert "hunter2" not in link and "topsecret" not in link and "upstream" not in link and "AETHER_" not in link
    assert link_omissions(original) == ["1 extra AETHER_* setting(s) (they may hold secrets)", "the upstream proxy (it has a login)"]
    # An upstream without a login is shared.
    assert "upstream=socks5://127.0.0.1:1080" in to_link(profile(upstream="socks5://127.0.0.1:1080"))
    assert link_omissions(profile(upstream="socks5://127.0.0.1:1080")) == []


@pytest.mark.parametrize(
    "link, fragment",
    [
        ("aether://nonsense", "unknown mode"),
        ("aether://masque?fragement=1", "unknown parameter"),
        ("aether://masque?fragment=maybe", "must be 1 or 0"),
        ("aether://masque?reconnect_secs=soon", "whole number"),
        ("aether://masque?transport=h9", "transport must be"),
        ("aether://wg?transport=h2", "UDP all the way"),
        ("aether://masque?block=a.example%2Cb.example,weird:thing", "unknown type"),
        ("aether://masque?outer=1.2.3.4", "no port"),
        ("aether://masque?wait=3", "at least 10 seconds"),
    ],
)
def test_bad_links_say_what_is_wrong(link, fragment):
    with pytest.raises(ParseError, match=fragment):
        parse_link(link)


def test_the_scheme_is_case_insensitive_and_the_name_defaults_to_a_description():
    parsed = parse_aether("AETHER://gool?transport=h2")
    assert parsed.name == "WARP gool/h2" and parsed.aether.mode == AetherMode.GOOL


def test_links_in_a_list_are_parsed_like_any_other():
    text = "# my links\naether://masque?transport=h2#one\ntrojan://pw@t.example.com:443#two\naether://nonsense\n"
    profiles, errors = parse_links(text)
    assert [p.name for p in profiles] == ["one", "two"]
    assert len(errors) == 1 and "unknown mode" in errors[0][1]


def test_a_chain_has_no_link():
    chain = Profile(name="c", protocol=Protocol.CHAIN, chain=[])
    with pytest.raises(ParseError, match="no share link"):
        to_link(chain)


# ---- through the CLI -----------------------------------------------------------------------------------


def test_add_takes_an_aether_link_like_any_other():
    result = runner.invoke(app, ["add", "aether://masque?transport=h2&fragment=1&noize=gfw#shared"])
    assert result.exit_code == 0, result.output
    (stored,) = ProfileStore().list()
    assert stored.is_aether and stored.name == "shared"
    assert (stored.aether.transport, stored.aether.fragment, stored.aether.noize) == ("h2", True, "gfw")


def test_profile_show_link_prints_it_and_says_what_was_left_out():
    runner.invoke(app, ["add", "aether", "--name", "W", "--h2", "--upstream", "socks5://u:pw@127.0.0.1:1080"])
    result = runner.invoke(app, ["profile", "show", "W", "--link"])
    assert result.exit_code == 0, result.output
    assert "aether://masque?transport=h2#W" in result.stdout
    assert "pw@" not in result.stdout
    assert "left out of the link: the upstream proxy (it has a login)" in result.stderr


def test_the_link_of_a_shown_profile_adds_the_same_profile_back():
    runner.invoke(app, ["add", "aether", "--name", "orig", "--h2", "--fragment", "--noize", "gfw", "--block", "ads.example"])
    link = runner.invoke(app, ["profile", "show", "orig", "--link"]).stdout.strip()
    runner.invoke(app, ["profile", "remove", "orig", "--yes"])
    assert runner.invoke(app, ["add", link]).exit_code == 0
    (stored,) = ProfileStore().list()
    assert stored.aether.fragment and stored.aether.route_block == ["ads.example"] and stored.name == "orig"
