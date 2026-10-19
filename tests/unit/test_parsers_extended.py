from __future__ import annotations

import pytest

from tests.helpers import free_links, read_fixture
from v2rm.errors import ParseError
from v2rm.models.enums import Protocol, SecurityKind, TransportKind
from v2rm.parsers import links, parse_link, parse_links, to_link

LINKS = free_links()


def by(pred):
    """The first sample link satisfying pred(parsed_query, raw_link)."""
    from urllib.parse import parse_qs, urlsplit

    for link in LINKS:
        q = {k: v[0] for k, v in parse_qs(urlsplit(link).query, keep_blank_values=True).items()}
        if pred(q, link):
            return link
    raise AssertionError("no sample link matches")


def test_sample_fixture_parses_without_errors_and_skips_the_header_comments():
    # The real header block contains many "https://..." comment lines.
    profiles, errors = parse_links(read_fixture("free_configs_sample.txt"))
    assert not errors, errors
    assert len(profiles) == len(LINKS) == 12


def test_variant_a_has_unsafe_fingerprint_cipher_suites_and_finalmask():
    p = parse_link(LINKS[0])
    assert p.protocol == Protocol.VLESS
    assert p.tls.fingerprint == "unsafe"  # passed through, not validated against a whitelist
    assert p.tls.cipher_suites.startswith("TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:")
    assert p.tls.cipher_suites.count(":") == 12  # 13 suites, colon-separated as Xray expects
    tcp_masks = p.transport.finalmask["tcp"]
    assert [m["type"] for m in tcp_masks] == ["fragment", "fragment"]
    assert tcp_masks[0]["settings"]["packets"] == "tlshello"
    assert tcp_masks[0]["settings"]["lengths"] == ["0", "104", "1"]
    assert p.encryption == ""  # encryption=none means no VLESS encryption
    assert p.tls.security == SecurityKind.TLS
    assert p.transport.network == TransportKind.WS
    assert p.transport.path == "/drsukitgreiusweqa9otrh983"
    assert p.tls.alpn == ["http/1.1"]


def test_variant_b_has_ech():
    p = parse_link(LINKS[1])
    assert p.tls.fingerprint == "chrome"
    assert p.tls.ech_config_list == "cloudflare-ech.com+udp://1.1.1.1"
    assert not p.tls.cipher_suites
    assert not p.transport.finalmask


def test_variant_c_is_plain_on_the_ipv6_edge_address():
    p = parse_link(LINKS[2])
    assert p.server == "2a06:98c1:3101::6812:202f"
    assert p.tls.fingerprint == "chrome"
    assert not p.tls.ech_config_list and not p.tls.cipher_suites and not p.transport.finalmask


def test_ech_parameter_aliases_echcl_and_echconfiglist():
    echcl = parse_link(by(lambda q, _: q.get("echcl")))
    echconfig = parse_link(by(lambda q, _: q.get("echConfigList")))
    assert echcl.tls.ech_config_list == "cloudflare-ech.com+udp://1.1.1.1"
    assert echconfig.tls.ech_config_list == "cloudflare-ech.com+udp://1.1.1.1"


def test_vless_mlkem_encryption_is_kept_verbatim():
    p = parse_link(by(lambda q, _: q.get("encryption", "").startswith("mlkem")))
    assert p.encryption.startswith("mlkem768x25519plus.native.0rtt.")
    assert "_" in p.encryption or len(p.encryption) > 40  # the key is part of the string
    assert to_link(p).count("mlkem768x25519plus.native.0rtt.") == 1


def test_xhttp_extra_and_mode_and_alpn():
    p = parse_link(by(lambda q, _: q.get("type") == "xhttp"))
    assert p.transport.network == TransportKind.XHTTP
    assert p.transport.mode == "auto"
    assert p.transport.xhttp_extra == {"xPaddingBytes": "100-1000"}
    assert p.tls.alpn == ["h2", "http/1.1"]
    assert p.transport.path.startswith("/?TELEGRAM")


def test_trojan_link_gets_the_extended_params_too():
    p = parse_link(by(lambda q, link: link.startswith("trojan://")))
    assert p.protocol == Protocol.TROJAN
    assert p.password
    assert p.tls.security == SecurityKind.TLS
    assert p.tls.fingerprint == "unsafe"
    assert p.tls.cipher_suites
    assert p.transport.finalmask["tcp"]


def test_headers_json_with_odd_spacing():
    p = parse_link(by(lambda q, _: q.get("headers")))
    assert p.transport.headers == {"Host": "snip.edgeoneai.cc.cd"}


def test_packet_encoding_both_spellings():
    a = parse_link(by(lambda q, _: q.get("packetEncoding")))
    b = parse_link(by(lambda q, _: q.get("packet-encoding")))
    assert a.packet_encoding == "xudp"
    assert b.packet_encoding == "xudp"


def test_legacy_fragment_is_preserved_not_dropped():
    p = parse_link(by(lambda q, _: q.get("fragment")))
    assert p.extra["fragment"] == "null,null,tlshello,0"


def test_every_sample_link_round_trips_through_to_link():
    for link in LINKS:
        p1 = parse_link(link)
        p2 = parse_link(to_link(p1))
        assert p2.identity_key() == p1.identity_key(), link[:80]
        assert p2.server == p1.server and p2.port == p1.port
        assert p2.tls.fingerprint == p1.tls.fingerprint
        assert p2.tls.cipher_suites == p1.tls.cipher_suites
        assert p2.tls.ech_config_list == p1.tls.ech_config_list
        assert p2.tls.alpn == p1.tls.alpn
        assert p2.transport.finalmask == p1.transport.finalmask
        assert p2.transport.xhttp_extra == p1.transport.xhttp_extra
        assert p2.transport.mode == p1.transport.mode
        assert p2.transport.headers == p1.transport.headers
        assert p2.transport.path == p1.transport.path
        assert p2.encryption == p1.encryption
        assert p2.packet_encoding == p1.packet_encoding
        assert p2.extra.get("fragment") == p1.extra.get("fragment")


def test_ipv6_server_survives_round_trip_with_brackets():
    p = parse_link(LINKS[2])
    link = to_link(p)
    assert "@[2a06:98c1:3101::6812:202f]:443" in link
    assert parse_link(link).server == p.server


def test_the_three_variants_of_one_node_have_distinct_identity_keys():
    keys = [parse_link(link).identity_key() for link in LINKS[:3]]
    assert len(set(keys)) == 3


def test_identity_keys_are_stable_across_reparses_and_distinct_across_the_sample():
    first = [parse_link(link).identity_key() for link in LINKS]
    second = [parse_link(link).identity_key() for link in LINKS]
    assert first == second
    assert len(set(first)) == len(LINKS)


def test_identity_key_ignores_the_display_name():
    link = LINKS[0]
    renamed = link.split("#")[0] + "#A%20completely%20different%20name"
    assert parse_link(link).identity_key() == parse_link(renamed).identity_key()


def test_headers_key_value_list_form():
    assert links.parse_headers("Host:example.com, X-Test: 1") == {"Host": "example.com", "X-Test": "1"}
    assert links.parse_headers("") == {}


def test_headers_rejects_a_malformed_list_entry():
    with pytest.raises(ParseError):
        links.parse_headers("Host example.com")


def test_invalid_json_in_fm_is_reported_not_silently_dropped():
    link = "vless://u@h.example.com:443?security=tls&type=ws&fm=%7Bnot-json"
    with pytest.raises(ParseError, match="fm"):
        parse_link(link)


def test_json_param_must_be_an_object():
    link = "vless://u@h.example.com:443?security=tls&type=ws&extra=%5B1%2C2%5D"
    with pytest.raises(ParseError, match="extra"):
        parse_link(link)


def test_one_malformed_link_in_a_list_is_reported_while_the_rest_import():
    text = LINKS[0] + "\nvless://u@h.example.com:443?fm=%7Bbroken\n" + LINKS[1] + "\n"
    profiles, errors = parse_links(text)
    assert len(profiles) == 2
    assert len(errors) == 1
    assert "fm" in errors[0][1]
