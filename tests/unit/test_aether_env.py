"""What an Aether profile turns into: the environment its process is started with."""

from __future__ import annotations

from pathlib import Path

from v2rm.engines.aether.env import (
    build_environment,
    describe_environment,
    effective_transport,
    scrubbed_environment,
)
from v2rm.models.aether import AetherMode, AetherSettings
from v2rm.net.proxy_url import parse_proxy_url

CONFIG = Path("/data/aether/p1/aether.toml")
SOCKS = "127.0.0.1:10808"


def env_for(notes=None, upstream=None, chained=False, http=None, **fields) -> dict[str, str]:
    return build_environment(
        AetherSettings(**fields),
        config_path=CONFIG,
        socks=SOCKS,
        http=http,
        upstream=parse_proxy_url(upstream) if upstream else None,
        chained=chained,
        notes=notes,
    )


# ---- the basics, identical for every mode ------------------------------------------------------


def test_a_plain_profile_names_everything_aether_would_otherwise_ask_about():
    env = env_for()
    assert env["AETHER_CONFIG"] == str(CONFIG)
    assert env["AETHER_SOCKS"] == SOCKS
    assert env["AETHER_PROTOCOL"] == "masque"
    assert env["AETHER_MASQUE_HTTP2"] == "0"  # HTTP/3 chosen out loud, not left to a prompt
    assert env["AETHER_SCAN"] == "balanced"
    assert env["AETHER_IP"] == "v4"
    assert env["AETHER_QUICK_RECONNECT"] == "1"
    assert env["AETHER_LOG_LEVEL"] == "info"
    assert "AETHER_HTTP_PROXY" not in env and "AETHER_UPSTREAM" not in env and "AETHER_NOIZE" not in env


def test_the_http_proxy_is_opt_in():
    assert env_for(http="127.0.0.1:10809")["AETHER_HTTP_PROXY"] == "127.0.0.1:10809"


# ---- modes -------------------------------------------------------------------------------------


def test_every_mode_picks_its_protocol():
    assert env_for(mode=AetherMode.WG)["AETHER_PROTOCOL"] == "wg"
    assert env_for(mode=AetherMode.GOOL)["AETHER_PROTOCOL"] == "gool"
    assert env_for(mode=AetherMode.MIM)["AETHER_PROTOCOL"] == "mim"
    classic = env_for(mode=AetherMode.GOOL_CLASSIC)
    assert classic["AETHER_PROTOCOL"] == "gool" and classic["AETHER_GOOL_MODE"] == "classic"
    assert "AETHER_GOOL_MODE" not in env_for(mode=AetherMode.GOOL)


def test_the_carrier_only_exists_for_the_masque_modes():
    assert env_for(transport="h2")["AETHER_MASQUE_HTTP2"] == "1"
    assert env_for(transport="h3")["AETHER_MASQUE_HTTP2"] == "0"
    assert env_for(mode=AetherMode.GOOL, transport="h2")["AETHER_MASQUE_HTTP2"] == "1"
    assert "AETHER_MASQUE_HTTP2" not in env_for(mode=AetherMode.WG)
    assert "AETHER_MASQUE_HTTP2" not in env_for(mode=AetherMode.GOOL_CLASSIC)


def test_quic_v2_opener_can_be_turned_off_for_the_masque_modes_only():
    assert env_for(quic_v2=False)["AETHER_QUIC_V2"] == "0"
    assert "AETHER_QUIC_V2" not in env_for()
    assert "AETHER_QUIC_V2" not in env_for(mode=AetherMode.WG, quic_v2=False)


# ---- gateways by hand --------------------------------------------------------------------------


def test_a_forced_masque_gateway():
    assert env_for(outer="162.159.198.1:443")["AETHER_PEER"] == "162.159.198.1:443"


def test_a_forced_wireguard_gateway():
    env = env_for(mode=AetherMode.WG, outer="162.159.192.1:2408")
    assert env["AETHER_WG_PEER"] == "162.159.192.1:2408" and "AETHER_PEER" not in env


def test_gool_over_masque_pins_the_masque_gateway_and_the_wireguard_endpoint_inside():
    env = env_for(mode=AetherMode.GOOL, outer="162.159.198.1:443", inner="188.114.96.1:2408")
    assert env["AETHER_PEER"] == "162.159.198.1:443"
    assert env["AETHER_GOOL_INNER"] == "188.114.96.1:2408"


def test_classic_gool_pins_both_hops_or_lets_the_scan_find_them():
    both = env_for(mode=AetherMode.GOOL_CLASSIC, outer="162.159.192.1:2408", inner="188.114.96.1:2408")
    assert both["AETHER_WIW_OUTER_PEER"] == "162.159.192.1:2408"
    assert both["AETHER_WIW_INNER_PEER"] == "188.114.96.1:2408"

    only_outer = env_for(mode=AetherMode.GOOL_CLASSIC, outer="162.159.192.1:2408")
    assert "AETHER_WIW_INNER_PEER" not in only_outer  # the scan finds the other hop

    scanned = env_for(mode=AetherMode.GOOL_CLASSIC)
    assert not any(key.startswith("AETHER_WIW") for key in scanned)


def test_masque_in_masque_hops():
    env = env_for(mode=AetherMode.MIM, outer="162.159.198.1:443", inner="162.159.199.1:443")
    assert env["AETHER_MIM_OUTER_PEER"] == "162.159.198.1:443"
    assert env["AETHER_MIM_INNER_PEER"] == "162.159.199.1:443"


# ---- the carrier through a proxy or a chain ----------------------------------------------------


def test_an_http_upstream_forces_the_tcp_carrier_with_a_note():
    notes: list[str] = []
    env = env_for(notes=notes, upstream="http://proxy.example:8080")
    assert env["AETHER_MASQUE_HTTP2"] == "1"
    assert env["AETHER_UPSTREAM"] == "http://proxy.example:8080"
    assert any("HTTP proxy" in n for n in notes)


def test_a_socks_upstream_keeps_quic():
    env = env_for(upstream="socks5://127.0.0.1:1080")
    assert env["AETHER_MASQUE_HTTP2"] == "0"
    assert env["AETHER_UPSTREAM"] == "socks5://127.0.0.1:1080"


def test_a_chained_profile_defaults_to_the_tcp_carrier_but_obeys_an_explicit_choice():
    notes: list[str] = []
    assert env_for(notes=notes, upstream="socks5://127.0.0.1:41000", chained=True)["AETHER_MASQUE_HTTP2"] == "1"
    assert any("previous hop" in n for n in notes)
    explicit = env_for(upstream="socks5://127.0.0.1:41000", chained=True, transport="h3")
    assert explicit["AETHER_MASQUE_HTTP2"] == "0"


def test_wireguard_has_no_carrier_to_change():
    assert effective_transport(AetherSettings(mode=AetherMode.WG), None, True, []) == ""


def test_credentials_in_an_upstream_reach_aether_percent_encoded():
    env = env_for(upstream="socks5://al%40ice:p%3Ass@127.0.0.1:1080")
    assert env["AETHER_UPSTREAM"] == "socks5://al%40ice:p%3Ass@127.0.0.1:1080"


# ---- scanning, obfuscation, fragmentation ------------------------------------------------------


def test_scan_ip_and_quick_reconnect_are_passed_through():
    env = env_for(scan="Verified", ip="BOTH", quick_reconnect=False)
    assert (env["AETHER_SCAN"], env["AETHER_IP"], env["AETHER_QUICK_RECONNECT"]) == ("verified", "both", "0")


def test_noize_is_only_set_when_asked_so_aether_picks_its_default_per_mode():
    assert env_for(noize="gfw")["AETHER_NOIZE"] == "gfw"
    assert "AETHER_NOIZE" not in env_for()


def test_fragmentation_on_the_http2_carrier():
    notes: list[str] = []
    env = env_for(notes=notes, transport="h2", fragment=True, fragment_size="8-16", fragment_delay="2-10")
    assert env["AETHER_MASQUE_H2_FRAGMENT"] == "1"
    assert env["AETHER_MASQUE_H2_FRAGMENT_SIZE"] == "8-16"
    assert env["AETHER_MASQUE_H2_FRAGMENT_DELAY"] == "2-10"
    assert notes == []


def test_fragmentation_on_http3_says_what_it_does_and_does_not_cover():
    notes: list[str] = []
    env = env_for(notes=notes, fragment=True)
    assert env["AETHER_MASQUE_H2_FRAGMENT"] == "1"
    assert any("not fragmented" in n for n in notes)


def test_no_fragment_variables_when_it_is_off():
    env = env_for(transport="h2")
    assert not any("FRAGMENT" in key for key in env)


def test_quick_reconnect_note_for_the_modes_that_cannot_remember():
    notes: list[str] = []
    env_for(notes=notes, mode=AetherMode.GOOL_CLASSIC)
    assert any("scans again" in n for n in notes)
    quiet: list[str] = []
    env_for(notes=quiet, mode=AetherMode.GOOL_CLASSIC, quick_reconnect=False)
    env_for(notes=quiet, mode=AetherMode.MASQUE)
    assert quiet == []


# ---- TLS and timers ----------------------------------------------------------------------------


def test_tls_options():
    env = env_for(
        sni="www.cloudflare.com",
        ech="auto",
        ech_dns="udp://1.1.1.1",
        ech_domain="cloudflare-ech.com",
        tls_ciphers="ECDHE-ECDSA-AES128-GCM-SHA256",
        tls_groups="X25519",
        disable_grease=True,
    )
    assert env["AETHER_MASQUE_SNI"] == "www.cloudflare.com"
    assert env["AETHER_ECH"] == "auto" and env["AETHER_ECH_DNS"] == "udp://1.1.1.1"
    assert env["AETHER_ECH_DOMAIN"] == "cloudflare-ech.com"
    assert env["AETHER_TLS_CIPHERS"] == "ECDHE-ECDSA-AES128-GCM-SHA256" and env["AETHER_TLS_GROUPS"] == "X25519"
    assert env["AETHER_DISABLE_GREASE"] == "1"


def test_timers_reach_both_the_masque_and_the_wireguard_side():
    env = env_for(reconnect_secs=3, startup_secs=45, validate_secs=15, no_data_check=True, keepalive=7)
    assert env["AETHER_MASQUE_RECONNECT_SECS"] == env["AETHER_WG_RECONNECT_SECS"] == "3"
    assert env["AETHER_MASQUE_STARTUP_SECS"] == "45"
    assert env["AETHER_MASQUE_VALIDATE_SECS"] == env["AETHER_WG_VALIDATE_SECS"] == "15"
    assert env["AETHER_MASQUE_NO_DATA_CHECK"] == env["AETHER_WG_NO_DATA_CHECK"] == "1"
    assert env["AETHER_WG_KEEPALIVE"] == "7"
    assert not any("RECONNECT_SECS" in k for k in env_for())


def test_dns_servers_are_comma_separated():
    assert env_for(dns=["1.1.1.1", "9.9.9.9"])["AETHER_DNS"] == "1.1.1.1,9.9.9.9"


# ---- routing -----------------------------------------------------------------------------------


def test_route_rules_are_one_per_line():
    env = env_for(route_block=["ads.example", "keyword:tracker"], route_direct=["private", "port:25", r"regexp:^ad[0-9]+\."])
    assert env["AETHER_ROUTE_BLOCK"] == "ads.example\nkeyword:tracker"
    assert env["AETHER_ROUTE_DIRECT"] == "private\nport:25\n" + r"regexp:^ad[0-9]+\."


def test_sniffing_is_on_unless_turned_off():
    assert "AETHER_ROUTE_SNIFF" not in env_for()
    assert env_for(route_sniff=False)["AETHER_ROUTE_SNIFF"] == "0"
    assert env_for(route_sniff_ms=800)["AETHER_ROUTE_SNIFF_MS"] == "800"


def test_no_route_variables_without_rules():
    assert not any(key.startswith("AETHER_ROUTE") for key in env_for())


# ---- the rest ----------------------------------------------------------------------------------


def test_exit_location_and_misc_options():
    env = env_for(exit_loc="!IR,RU", exit_loc_secs=30, mark="0xff", api_address="188.114.97.6:443", perf="LOW", stats=True, log_level="Debug")
    assert env["AETHER_EXIT_LOC"] == "!IR,RU" and env["AETHER_EXIT_LOC_SECS"] == "30"
    assert env["AETHER_MARK"] == "0xff" and env["AETHER_API_ADDRESS"] == "188.114.97.6:443"
    assert env["AETHER_PERF_PROFILE"] == "low" and env["AETHER_STATS"] == "1"
    assert env["AETHER_LOG_LEVEL"] == "debug"


def test_extra_variables_are_passed_on_but_never_over_what_v2rm_owns():
    env = env_for(env={"AETHER_TEAM": "acme", "AETHER_SOCKS": "0.0.0.0:1", "AETHER_NOIZE": "light"}, noize="gfw")
    assert env["AETHER_TEAM"] == "acme"
    assert env["AETHER_SOCKS"] == SOCKS
    assert env["AETHER_NOIZE"] == "light"  # an explicit escape hatch may override the profile's own setting


def test_the_environment_a_child_inherits_loses_every_aether_and_rust_log_variable():
    base = {"PATH": "/usr/bin", "AETHER_SOCKS": "0.0.0.0:1819", "aether_x": "1", "RUST_LOG": "trace", "HOME": "/h"}
    assert scrubbed_environment(base) == {"PATH": "/usr/bin", "HOME": "/h"}


def test_describing_an_environment_hides_secrets():
    lines = describe_environment(
        {
            "AETHER_SOCKS": "127.0.0.1:1",
            "AETHER_UPSTREAM": "socks5://alice:hunter2@127.0.0.1:1080",
            "AETHER_ACCESS_CLIENT_SECRET": "topsecret",
            "AETHER_ACCESS_TOKEN": "jwt",
            "AETHER_ROUTE_BLOCK": "a.example\nb.example",
        }
    )
    text = "\n".join(lines)
    assert "hunter2" not in text and "topsecret" not in text and "jwt" not in text
    assert "AETHER_UPSTREAM=socks5://alice:***@127.0.0.1:1080" in lines
    assert "AETHER_ACCESS_CLIENT_SECRET=***" in lines
    assert "AETHER_SOCKS=127.0.0.1:1" in lines
