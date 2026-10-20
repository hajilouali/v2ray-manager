"""v2rm refuses what Aether would refuse -- and, more importantly, what it would silently ignore."""

from __future__ import annotations

import pytest

from v2rm.errors import ProfileValidationError
from v2rm.models.aether import AetherMode, AetherSettings
from v2rm.parsers.aether import build_profile, parse_endpoint, parse_route_entry, valid_domain, validate_settings


def ok(**fields) -> AetherSettings:
    settings = AetherSettings(**fields)
    validate_settings(settings)
    return settings


def bad(match: str, **fields) -> None:
    with pytest.raises(ProfileValidationError, match=match):
        validate_settings(AetherSettings(**fields))


# ---- endpoints -------------------------------------------------------------------------------


def test_endpoints_are_ip_and_port():
    assert parse_endpoint("162.159.192.1:2408") == "162.159.192.1:2408"
    assert parse_endpoint(" [2606:4700::1]:2408 ") == "[2606:4700::1]:2408"


@pytest.mark.parametrize(
    "text, fragment",
    [
        ("162.159.192.1", "no port"),
        ("2606:4700::1", "no port"),
        ("[2606:4700::1]", "no port"),
        ("2606:4700::1:2408", "not an endpoint"),
        ("example.com:443", "not an endpoint"),
        ("162.159.192.1:0", "invalid port"),
        ("162.159.192.1:70000", "invalid port"),
        ("162.159.192.1:http", "invalid port"),
        ("", "not an endpoint"),
    ],
)
def test_bad_endpoints_say_why(text, fragment):
    with pytest.raises(ProfileValidationError, match=fragment):
        parse_endpoint(text, "outer gateway")


def test_the_two_hops_need_different_edges():
    bad("separate edges", mode=AetherMode.GOOL_CLASSIC, outer="162.159.192.1:2408", inner="162.159.192.1:2409")
    bad("separate edges", mode=AetherMode.MIM, outer="162.159.192.1:443", inner="162.159.192.1:8443")
    ok(mode=AetherMode.GOOL_CLASSIC, outer="162.159.192.1:2408", inner="188.114.96.1:2408")
    # Gool over MASQUE dials a WireGuard endpoint *inside* the tunnel: the same address is fine.
    ok(mode=AetherMode.GOOL, outer="162.159.192.1:443", inner="162.159.192.1:2408")


def test_an_inner_hop_only_makes_sense_for_the_two_hop_modes():
    bad("single hop", mode=AetherMode.MASQUE, inner="188.114.96.1:2408")
    bad("single hop", mode=AetherMode.WG, inner="188.114.96.1:2408")
    ok(mode=AetherMode.GOOL, inner="188.114.96.1:2408")


# ---- transport and mode ------------------------------------------------------------------------


def test_wireguard_modes_have_no_http2_carrier():
    bad("UDP all the way", mode=AetherMode.WG, transport="h2")
    bad("UDP all the way", mode=AetherMode.GOOL_CLASSIC, transport="h2")
    ok(mode=AetherMode.MASQUE, transport="h2")
    ok(mode=AetherMode.GOOL, transport="h2")
    ok(mode=AetherMode.MIM, transport="h2")
    ok(mode=AetherMode.WG, transport="h3")


def test_choices_are_checked():
    bad("transport must be", transport="h4")
    bad("scan must be", scan="fast")
    bad("ip must be", ip="v5")
    bad("noize must be", noize="stealth")
    bad("perf must be", perf="ultra")
    bad("log level must be", log_level="loud")
    ok(scan="Verified", ip="BOTH", noize="GFW")  # case does not matter


def test_the_h2_peer_belongs_to_the_masque_carriers():
    bad("h2 peer only applies", mode=AetherMode.WG, h2_peer="1.1.1.1:443")
    ok(mode=AetherMode.MASQUE, h2_peer="1.1.1.1:443")
    bad("no port", mode=AetherMode.MASQUE, h2_peer="1.1.1.1")


# ---- fragmentation -----------------------------------------------------------------------------


def test_fragment_sizes_and_delays():
    ok(fragment=True, fragment_size="8-16", fragment_delay="2-10")
    ok(fragment=True, fragment_size="10", fragment_delay="0")
    bad("number or a range", fragment=True, fragment_size="big")
    bad("not a valid range", fragment=True, fragment_size="16-8")
    bad("not a valid range", fragment=True, fragment_size="0")
    bad("only take effect", fragment_size="8-16")


# ---- TLS ---------------------------------------------------------------------------------------


def test_sni_must_be_a_domain_not_an_address():
    ok(sni="www.cloudflare.com")
    ok(sni="consumer-masque.cloudflareclient.com.")
    bad("no domain name", sni="1.2.3.4")
    bad("no domain name", sni="not a name")
    bad("no domain name", sni="a..b")


def test_valid_domain_follows_aethers_rule():
    assert valid_domain("a_b.example.com") and valid_domain("x.y.")
    assert not valid_domain("") and not valid_domain("a" * 64 + ".com") and not valid_domain("a b")


def test_ech_forms():
    ok(ech="auto", ech_dns="https://1.1.1.1/dns-query@address=2.2.2.2@sni=google.com", ech_domain="cloudflare-ech.com")
    ok(ech="AEX+/wA=")
    bad("ech must be", ech="not base64!")
    bad("udp://, tcp:// or https://", ech_dns="1.1.1.1")
    bad("no domain name", ech_domain="not a domain")


def test_cipher_and_group_lists():
    ok(tls_ciphers="ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256", tls_groups="P-256:X25519")
    bad("tls ciphers", tls_ciphers="has space")
    bad("tls groups", tls_groups="a b")


# ---- timers, dns, misc -------------------------------------------------------------------------


def test_timers_are_positive():
    ok(reconnect_secs=2, startup_secs=30, validate_secs=10, keepalive=5, exit_loc_secs=60, route_sniff_ms=400)
    bad("reconnect delay", reconnect_secs=-1)
    bad("startup timeout", startup_secs=-5)


def test_dns_servers_are_addresses():
    ok(dns=["1.1.1.1", "2606:4700:4700::1111"])
    bad("not an IP address", dns=["dns.example"])


def test_exit_location_must_be_country_codes_never_silently_off():
    ok(exit_loc="!IR,AZ,RU")
    ok(exit_loc="DE,SE")
    ok(exit_loc="off")
    bad("country codes", exit_loc="Germany")
    bad("country codes", exit_loc="!IRN")
    bad("country codes", exit_loc="DE;SE")


def test_mark_and_api_address():
    ok(mark="0xff", api_address="188.114.97.6:443")
    ok(mark="255", api_address="api.cloudflareclient.com")
    ok(api_address="[2606:4700::1]:8443")
    bad("mark", mark="ff")
    bad("api address", api_address="bad host!")
    bad("invalid port", api_address="1.2.3.4:99999")


# ---- upstream ----------------------------------------------------------------------------------


def test_upstream_forms():
    ok(upstream="socks5://127.0.0.1:1080")
    ok(upstream="socks5://u:p@127.0.0.1:1080")
    ok(upstream="127.0.0.1:1080")
    ok(upstream="http://proxy.example:8080", transport="h2")
    ok(upstream="http://proxy.example:8080")  # the carrier becomes h2 by itself at start
    bad("plain HTTP", upstream="https://proxy.example:8443")
    bad("no port", upstream="socks5://127.0.0.1")


def test_an_http_upstream_cannot_carry_udp():
    bad("can't carry UDP", upstream="http://proxy.example:8080", transport="h3")
    bad("can't carry UDP", upstream="http://proxy.example:8080", mode=AetherMode.WG)
    bad("can't carry UDP", upstream="http://proxy.example:8080", mode=AetherMode.GOOL_CLASSIC)
    ok(upstream="socks5://127.0.0.1:1080", mode=AetherMode.WG)


# ---- routing rules ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "entry, expected",
    [
        ("example.com", ("domain", "example.com")),
        ("*.Example.COM", ("domain", "example.com")),
        ("domain:example.com", ("domain", "example.com")),
        ("suffix:example.com", ("domain", "example.com")),
        ("full:www.example.com", ("full", "www.example.com")),
        ("keyword:Doubleclick", ("keyword", "doubleclick")),
        (r"regexp:^ad[0-9]+\.", ("regexp", r"^ad[0-9]+\.")),
        ("10.0.0.0/8", ("ip", "10.0.0.0/8")),
        ("1.2.3.4", ("ip", "1.2.3.4/32")),
        ("ip:2001:db8::/32", ("ip", "2001:db8::/32")),
        ("cidr:192.168.0.0/16", ("ip", "192.168.0.0/16")),
        ("port:25", ("port", "25")),
        ("port:3010-3000", ("port", "3000-3010")),
        ("private", ("private", "")),
        ("geoip:private", ("private", "")),
        ("localhost", ("domain", "localhost")),
    ],
)
def test_route_entries_are_read_the_way_aether_reads_them(entry, expected):
    assert parse_route_entry(entry) == expected


@pytest.mark.parametrize(
    "entry, fragment",
    [
        ("", "empty"),
        ("a.example,b.example", "separator"),
        ("a.example;b.example", "separator"),
        ("# comment", "comment"),
        ("regexp:a{1,3}", "separator"),
        ("regexp:(unclosed", "regular expression"),
        (r"regexp:(?=foo)bar", "lookaround"),
        (r"regexp:(a)\1", "lookaround"),
        ("regexp:", "pattern"),
        ("keyword:", "word"),
        ("full:", "domain name"),
        ("ip:nonsense", "IP address or network"),
        ("port:abc", "port or a range"),
        ("port:70000", "outside"),
        ("geoip:ir", "no geo databases"),
        ("geosite:category-ads", "no geo databases"),
        ("2001:db8::/32", "ip: prefix"),
        ("::1", "ip: prefix"),
        ("weird:thing", "unknown type"),
        ("not a rule", "not a domain"),
    ],
)
def test_route_entries_aether_would_drop_are_refused(entry, fragment):
    with pytest.raises(ProfileValidationError, match=fragment):
        parse_route_entry(entry)


def test_every_rule_of_both_lists_is_checked():
    ok(route_block=["ads.example", "keyword:tracker"], route_direct=["private", "port:25", "10.0.0.0/8"])
    bad("unknown type", route_block=["ads.example", "weird:thing"])
    bad("not a domain", route_direct=["private", "not a rule"])


# ---- the extra environment ---------------------------------------------------------------------


def test_extra_environment_variables():
    ok(env={"AETHER_TEAM": "acme", "AETHER_TOR_DIR": "/var/lib/tor"})
    bad("not an AETHER_\\* variable", env={"PATH": "/x"})
    bad("not an AETHER_\\* variable", env={"aether_team": "x"})
    bad("managed by v2rm", env={"AETHER_SOCKS": "0.0.0.0:1"})
    bad("managed by v2rm", env={"AETHER_UPSTREAM": "socks5://x:1"})
    bad("managed by v2rm", env={"AETHER_CONFIG": "/etc/x"})
    bad("NUL", env={"AETHER_TEAM": "a\x00b"})


# ---- building a profile ------------------------------------------------------------------------


def test_build_profile_validates_and_names_it():
    profile = build_profile(AetherSettings(transport="h2", fragment=True))
    assert profile.name == "WARP masque/h2 +fragment"
    assert profile.aether.transport == "h2"
    assert build_profile(AetherSettings(), name="  my warp ").name == "my warp"
    with pytest.raises(ProfileValidationError):
        build_profile(AetherSettings(transport="h9"))
