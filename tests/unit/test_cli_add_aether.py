from __future__ import annotations

import os

from typer.testing import CliRunner

from v2rm.cli.app import app
from v2rm.models.aether import AetherMode
from v2rm.store import paths
from v2rm.store.profiles import ProfileStore

runner = CliRunner()


def add(*args: str):
    return runner.invoke(app, ["add", "aether", *args])


def stored():
    (profile,) = ProfileStore().list()
    return profile


def test_a_plain_add_makes_a_masque_profile_that_scans_for_its_gateway():
    result = add()
    assert result.exit_code == 0, result.output
    profile = stored()
    assert profile.is_aether and profile.aether.mode == AetherMode.MASQUE
    assert profile.name == "WARP masque"
    assert "registers a free anonymous Cloudflare WARP device" in result.output

    listed = runner.invoke(app, ["profile", "list"])
    assert "aether" in listed.output and "WARP masque" in listed.output


def test_http2_with_fragmentation_and_an_obfuscation_profile():
    result = add("--name", "h2 frag", "--h2", "--fragment", "--fragment-size", "8-16", "--fragment-delay", "2-10", "--noize", "gfw")
    assert result.exit_code == 0, result.output
    s = stored().aether
    assert (s.transport, s.fragment, s.fragment_size, s.fragment_delay, s.noize) == ("h2", True, "8-16", "2-10", "gfw")
    assert stored().name == "h2 frag"
    assert "ClientHello" not in result.output  # the hint is for fragmentation on HTTP/3 only


def test_fragmentation_on_http3_explains_what_it_covers():
    result = add("--fragment")
    assert result.exit_code == 0, result.output
    assert "add --transport h2" in result.output


def test_classic_gool_with_both_hops_named_by_hand():
    result = add("--mode", "gool-classic", "--outer", "162.159.192.1:2408", "--inner", "188.114.96.1:2408")
    assert result.exit_code == 0, result.output
    s = stored().aether
    assert s.mode == AetherMode.GOOL_CLASSIC and s.outer == "162.159.192.1:2408" and s.inner == "188.114.96.1:2408"


def test_classic_gool_scans_for_both_hops_when_none_are_named():
    assert add("--mode", "gool-classic").exit_code == 0
    s = stored().aether
    assert s.outer == "" and s.inner == ""


def test_routing_rules_upstream_and_the_rest():
    result = add(
        "--block", "ads.example", "--block", "keyword:tracker",
        "--direct", "private", "--direct", "port:25",
        "--no-sniff", "--sniff-ms", "800",
        "--upstream", "socks5://127.0.0.1:1080",
        "--dns", "1.1.1.1", "--dns", "9.9.9.9",
        "--scan", "verified", "--ip", "both", "--exit-loc", "!IR,RU", "--perf", "low",
        "--no-quick-reconnect", "--reconnect-secs", "3", "--sni", "www.cloudflare.com",
        "--ech", "auto", "--env", "AETHER_TEAM=acme",
    )
    assert result.exit_code == 0, result.output
    s = stored().aether
    assert s.route_block == ["ads.example", "keyword:tracker"] and s.route_direct == ["private", "port:25"]
    assert s.route_sniff is False and s.route_sniff_ms == 800
    assert s.upstream == "socks5://127.0.0.1:1080" and s.dns == ["1.1.1.1", "9.9.9.9"]
    assert (s.scan, s.ip, s.exit_loc, s.perf) == ("verified", "both", "!IR,RU", "low")
    assert s.quick_reconnect is False and s.reconnect_secs == 3 and s.sni == "www.cloudflare.com"
    assert s.ech == "auto" and s.env == {"AETHER_TEAM": "acme"}


def test_how_long_connect_waits_can_be_set():
    assert add("--wait", "300").exit_code == 0
    assert stored().aether.wait_secs == 300
    result = add("--wait", "3")
    assert result.exit_code != 0 and "at least 10 seconds" in str(result.exception)


def test_quic_v2_and_grease_switches():
    assert add("--no-quic-v2", "--disable-grease").exit_code == 0
    s = stored().aether
    assert s.quic_v2 is False and s.disable_grease is True


def test_mistakes_are_refused_and_nothing_is_stored():
    cases = [
        (["--mode", "nonsense"], "Unknown mode"),
        (["--mode", "wg", "--h2"], "UDP all the way"),
        (["--h2", "--h3"], "not both"),
        (["--transport", "h2", "--h3"], "not both"),
        (["--outer", "162.159.192.1"], "no port"),
        (["--inner", "162.159.192.1:2408"], "single hop"),
        (["--block", "a.example,b.example"], "separator"),
        (["--direct", "geoip:ir"], "no geo databases"),
        (["--block", "2001:db8::/32"], "ip: prefix"),
        (["--exit-loc", "Germany"], "country codes"),
        (["--upstream", "https://proxy.example:8443"], "plain HTTP"),
        (["--upstream", "http://proxy.example:8080", "--mode", "wg"], "can't carry UDP"),
        (["--noize", "stealth"], "noize must be"),
        (["--env", "PATH=/x"], "not an AETHER_"),
        (["--env", "nonsense"], "AETHER_NAME=value"),
        (["--fragment-size", "8-16"], "only take effect"),
        (["--sni", "1.2.3.4"], "no domain name"),
    ]
    for args, fragment in cases:
        result = add(*args)
        assert result.exit_code != 0, (args, result.output)
        assert fragment in str(result.exception), (args, str(result.exception))
    assert ProfileStore().list() == []


# ---- importing an identity --------------------------------------------------------------------------


IDENTITY = 'device_id = "d"\naccess_token = "t"\nwg_private_key = "AAAA"\nwg_peer_public_key = "AAAA"\n'


def test_an_existing_identity_is_copied_to_where_the_mode_reads_it(tmp_path):
    source = tmp_path / "aether.toml"
    source.write_text(IDENTITY)
    result = add("--identity-file", str(source))
    assert result.exit_code == 0, result.output

    target = paths.aether_profile_dir(stored().id) / "aether-masque.toml"
    assert target.read_text() == IDENTITY
    if os.name == "posix":
        assert target.stat().st_mode & 0o077 == 0  # private keys: owner only
    assert "registers a free anonymous" not in result.output


def test_a_wireguard_profile_reads_its_identity_from_the_base_file(tmp_path):
    source = tmp_path / "id.toml"
    source.write_text(IDENTITY)
    assert add("--mode", "wg", "--identity-file", str(source)).exit_code == 0
    assert (paths.aether_profile_dir(stored().id) / "aether.toml").exists()


def test_a_file_that_is_not_an_identity_is_refused_and_the_profile_not_kept(tmp_path):
    source = tmp_path / "junk.toml"
    source.write_text("hello = 1\n")
    result = add("--identity-file", str(source))
    assert result.exit_code != 0 and "does not look like an Aether identity" in str(result.exception)
    assert ProfileStore().list() == []


def test_a_missing_identity_file_is_refused(tmp_path):
    result = add("--identity-file", str(tmp_path / "nope.toml"))
    assert result.exit_code != 0 and "not found" in str(result.exception)
    assert ProfileStore().list() == []


# ---- the menu ---------------------------------------------------------------------------------------


def test_the_menu_can_add_an_aether_profile():
    answers = [
        "15",  # the menu entry
        "masque",  # mode
        "h2",  # carrier
        "y",  # fragment?
        "8-16",  # size
        "2-10",  # delay
        "gfw",  # noize
        "n",  # gateway by hand?
        "socks5://127.0.0.1:1080",  # upstream
        "menu warp",  # name
        "0",
    ]
    result = runner.invoke(app, ["menu"], input="\n".join(answers) + "\n")
    assert result.exit_code == 0, result.output
    profile = stored()
    assert profile.name == "menu warp"
    s = profile.aether
    assert (s.transport, s.fragment, s.fragment_size, s.noize, s.upstream) == ("h2", True, "8-16", "gfw", "socks5://127.0.0.1:1080")


def test_the_menu_adds_a_wireguard_profile_without_asking_about_a_carrier():
    answers = ["15", "wg", "", "n", "", "", "0"]  # mode, noize, gateway by hand?, upstream, name
    result = runner.invoke(app, ["menu"], input="\n".join(answers) + "\n")
    assert result.exit_code == 0, result.output
    assert stored().aether.mode == AetherMode.WG


def test_the_menu_reports_a_mistake_instead_of_crashing():
    answers = ["15", "masque", "h3", "stealth", "n", "", "", "0"]  # mode, carrier, noize (wrong), ...
    result = runner.invoke(app, ["menu"], input="\n".join(answers) + "\n")
    assert result.exit_code == 0, result.output
    assert "noize must be" in result.output
    assert ProfileStore().list() == []
