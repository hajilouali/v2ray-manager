from __future__ import annotations

import pytest

from tests.helpers import free_links, link_with
from v2rm.engines.xray.generate import generate_config, needs_preflight
from v2rm.errors import ProfileValidationError, UnsupportedFeatureError
from v2rm.models.auth import ProxyAuth
from v2rm.models.enums import Protocol, SecurityKind, TransportKind
from v2rm.models.profile import Profile, TlsSettings, TransportSettings
from v2rm.parsers import parse_link
from v2rm.routing.presets import GLOBAL

LINKS = free_links()


def outbound_of(profile: Profile, **kw) -> dict:
    return generate_config(profile, GLOBAL, 10808, 10809, **kw)["outbounds"][0]


def stream_of(profile: Profile) -> dict:
    return outbound_of(profile)["streamSettings"]


# ---- extended link parameters land in the right place -----------------------


def test_variant_a_cipher_suites_fingerprint_and_finalmask():
    p = parse_link(LINKS[0])
    out = outbound_of(p)
    stream = out["streamSettings"]
    assert out["protocol"] == "vless"
    assert out["settings"]["vnext"][0]["users"][0]["encryption"] == "none"
    assert stream["network"] == "ws"
    assert stream["security"] == "tls"
    tls = stream["tlsSettings"]
    assert tls["fingerprint"] == "unsafe"
    assert tls["cipherSuites"] == p.tls.cipher_suites  # colon-separated string, as Xray expects
    assert tls["serverName"] == "server5.9966338.xyz"
    assert tls["alpn"] == ["http/1.1"]
    assert "echConfigList" not in tls
    assert stream["finalmask"] == p.transport.finalmask
    assert stream["finalmask"]["tcp"][0]["settings"]["packets"] == "tlshello"


def test_variant_b_ech():
    tls = stream_of(parse_link(LINKS[1]))["tlsSettings"]
    assert tls["echConfigList"] == "cloudflare-ech.com+udp://1.1.1.1"
    assert tls["fingerprint"] == "chrome"
    assert "cipherSuites" not in tls
    assert "finalmask" not in stream_of(parse_link(LINKS[1]))


def test_ws_uses_the_independent_host_field_not_a_host_header():
    ws = stream_of(parse_link(LINKS[0]))["wsSettings"]
    assert ws["host"] == "server5.9966338.xyz"
    assert ws["path"] == "/drsukitgreiusweqa9otrh983"
    assert "headers" not in ws


def test_a_host_header_in_headers_is_folded_into_host_and_other_headers_are_kept():
    p = parse_link(link_with(lambda q, _: q.get("headers")))
    assert p.transport.headers == {"Host": "snip.edgeoneai.cc.cd"}
    ws = stream_of(p)["wsSettings"]
    assert ws["host"] == "snip.edgeoneai.cc.cd"
    assert "headers" not in ws  # Host was the only header

    p.transport.headers = {"Host": "ignored.example.com", "X-Token": "abc"}
    ws = stream_of(p)["wsSettings"]
    assert ws["host"] == "snip.edgeoneai.cc.cd"  # the explicit host param wins
    assert ws["headers"] == {"X-Token": "abc"}


def test_vless_post_quantum_encryption_is_emitted_verbatim():
    p = parse_link(link_with(lambda q, _: q.get("encryption", "").startswith("mlkem")))
    user = outbound_of(p)["settings"]["vnext"][0]["users"][0]
    assert user["encryption"] == p.encryption
    assert user["encryption"].startswith("mlkem768x25519plus.native.0rtt.")


def test_xhttp_with_extra_and_mode():
    p = parse_link(link_with(lambda q, _: q.get("type") == "xhttp"))
    stream = stream_of(p)
    assert stream["network"] == "xhttp"
    xhttp = stream["xhttpSettings"]
    assert xhttp["mode"] == "auto"
    assert xhttp["host"] == "dd.servicevip.cc.cd"
    assert xhttp["path"].startswith("/?TELEGRAM")
    assert xhttp["extra"] == {"xPaddingBytes": "100-1000"}
    assert stream["tlsSettings"]["alpn"] == ["h2", "http/1.1"]


def test_xhttp_custom_headers_move_inside_extra_because_extra_replaces_the_outer_config():
    p = parse_link(link_with(lambda q, _: q.get("type") == "xhttp"))
    p.transport.headers = {"Host": "h.example.com", "X-A": "1"}
    p.transport.host = ""
    xhttp = stream_of(p)["xhttpSettings"]
    assert xhttp["host"] == "h.example.com"
    assert xhttp["extra"]["headers"] == {"X-A": "1"}
    assert "headers" not in xhttp  # a Host header here would be an Xray error


def test_xhttp_without_extra_keeps_headers_on_the_outer_config():
    p = Profile(
        name="x", protocol=Protocol.VLESS, server="s.example.com", port=443, uuid="u",
        transport=TransportSettings(network=TransportKind.XHTTP, path="/p", host="h.example.com", headers={"X-A": "1"}),
        tls=TlsSettings(security=SecurityKind.TLS, sni="s.example.com"),
    )
    xhttp = stream_of(p)["xhttpSettings"]
    assert xhttp["headers"] == {"X-A": "1"}
    assert "extra" not in xhttp


def test_an_unknown_xhttp_mode_is_not_emitted():
    p = Profile(
        name="x", protocol=Protocol.VLESS, server="s.example.com", port=443, uuid="u",
        transport=TransportSettings(network=TransportKind.XHTTP, mode="bogus"),
        tls=TlsSettings(security=SecurityKind.TLS),
    )
    assert "mode" not in stream_of(p)["xhttpSettings"]


def test_httpupgrade_uses_independent_host():
    p = Profile(
        name="h", protocol=Protocol.VLESS, server="s.example.com", port=443, uuid="u",
        transport=TransportSettings(
            network=TransportKind.HTTPUPGRADE, path="/u", headers={"Host": "h.example.com", "X-A": "1"}
        ),
        tls=TlsSettings(security=SecurityKind.TLS),
    )
    hu = stream_of(p)["httpupgradeSettings"]
    assert hu["host"] == "h.example.com"
    assert hu["headers"] == {"X-A": "1"}


def test_trojan_link_gets_the_same_tls_and_finalmask_treatment():
    p = parse_link(link_with(lambda q, link: link.startswith("trojan://")))
    out = outbound_of(p)
    assert out["protocol"] == "trojan"
    assert out["streamSettings"]["tlsSettings"]["cipherSuites"] == p.tls.cipher_suites
    assert out["streamSettings"]["finalmask"] == p.transport.finalmask


def test_finalmask_alone_on_plain_tcp_still_produces_stream_settings():
    p = Profile(
        name="m", protocol=Protocol.VLESS, server="s.example.com", port=443, uuid="u",
        transport=TransportSettings(finalmask={"tcp": [{"type": "fragment", "settings": {}}]}),
    )
    stream = stream_of(p)
    assert stream["network"] == "tcp"
    assert stream["finalmask"] == {"tcp": [{"type": "fragment", "settings": {}}]}


def test_plain_tcp_without_tls_or_finalmask_still_has_no_stream_settings():
    p = Profile(name="s", protocol=Protocol.SHADOWSOCKS, server="s.example.com", port=1, method="aes-128-gcm", password="p")
    assert "streamSettings" not in outbound_of(p)


# ---- things this Xray build rejects are reported, not emitted ---------------


@pytest.mark.parametrize("network", [TransportKind.HTTP, TransportKind.QUIC])
def test_removed_transports_raise_a_clear_error(network):
    p = Profile(
        name="x", protocol=Protocol.VLESS, server="s.example.com", port=443, uuid="u",
        transport=TransportSettings(network=network), tls=TlsSettings(security=SecurityKind.TLS),
    )
    with pytest.raises(UnsupportedFeatureError, match="removed"):
        generate_config(p, GLOBAL, 1, 2)


def test_allow_insecure_raises_because_xray_removed_it():
    p = Profile(
        name="x", protocol=Protocol.VLESS, server="s.example.com", port=443, uuid="u",
        tls=TlsSettings(security=SecurityKind.TLS, allow_insecure=True),
    )
    with pytest.raises(UnsupportedFeatureError, match="allowInsecure"):
        generate_config(p, GLOBAL, 1, 2)


def test_allow_insecure_is_irrelevant_without_tls():
    p = Profile(
        name="x", protocol=Protocol.VLESS, server="127.0.0.1", port=443, uuid="u",
        tls=TlsSettings(security=SecurityKind.NONE, allow_insecure=True),
    )
    generate_config(p, GLOBAL, 1, 2)  # must not raise


# ---- notes --------------------------------------------------------------------


def test_legacy_fragment_is_noted_not_silently_dropped():
    notes: list[str] = []
    generate_config(parse_link(link_with(lambda q, _: q.get("fragment"))), GLOBAL, 1, 2, notes=notes)
    assert any("fragment=null,null,tlshello,0" in n for n in notes)


def test_packet_encoding_xudp_needs_no_note_but_other_values_get_one():
    xudp = parse_link(link_with(lambda q, _: q.get("packetEncoding")))
    notes: list[str] = []
    generate_config(xudp, GLOBAL, 1, 2, notes=notes)
    assert not any("packetEncoding" in n for n in notes)

    xudp.packet_encoding = "packet"
    generate_config(xudp, GLOBAL, 1, 2, notes=notes)
    assert any("packetEncoding=packet" in n for n in notes)


def test_no_notes_for_a_clean_profile():
    notes: list[str] = []
    generate_config(parse_link(LINKS[0]), GLOBAL, 1, 2, notes=notes)
    assert notes == []


# ---- inbounds: listen address and auth ----------------------------------------


@pytest.mark.parametrize("listen", ["127.0.0.1", "0.0.0.0", "172.18.0.1"])
def test_inbounds_use_the_configured_listen_address(listen):
    config = generate_config(parse_link(LINKS[0]), GLOBAL, 10808, 10809, listen_address=listen)
    assert [(i["protocol"], i["listen"], i["port"]) for i in config["inbounds"]] == [
        ("socks", listen, 10808),
        ("http", listen, 10809),
    ]


def test_auth_accounts_appear_in_every_inbound():
    config = generate_config(parse_link(LINKS[0]), GLOBAL, 10808, 10809, auth=ProxyAuth("demo", "demo-pass"))
    socks, http = config["inbounds"]
    assert socks["settings"]["auth"] == "password"
    assert socks["settings"]["accounts"] == [{"user": "demo", "pass": "demo-pass"}]
    assert http["settings"]["accounts"] == [{"user": "demo", "pass": "demo-pass"}]


def test_without_auth_the_socks_inbound_is_noauth():
    config = generate_config(parse_link(LINKS[0]), GLOBAL, 10808, 10809)
    socks, http = config["inbounds"]
    assert socks["settings"]["auth"] == "noauth"
    assert "accounts" not in socks["settings"] and "accounts" not in http["settings"]


def test_udp_associate_ip_is_set_only_for_a_specific_non_loopback_address():
    p = parse_link(LINKS[0])
    assert generate_config(p, GLOBAL, 1, 2, listen_address="172.17.0.1")["inbounds"][0]["settings"]["ip"] == "172.17.0.1"
    assert "ip" not in generate_config(p, GLOBAL, 1, 2, listen_address="127.0.0.1")["inbounds"][0]["settings"]
    assert "ip" not in generate_config(p, GLOBAL, 1, 2, listen_address="0.0.0.0")["inbounds"][0]["settings"]


# ---- MASQUE ------------------------------------------------------------------


def masque(**extra) -> Profile:
    return parse_link(
        "masque://alice:s3cret@m.example.com:443?sni=front.example.com&path=%2Fmasque"
        "&host=h.example.com&fp=chrome" + "".join(f"&{k}={v}" for k, v in extra.items())
    )


def test_masque_outbound_matches_the_xray_structure_exactly():
    out = outbound_of(masque())
    assert out == {
        "tag": "proxy",
        "protocol": "masque",
        "settings": {"address": "m.example.com", "port": 443},
        "streamSettings": {
            "network": "masque",
            "security": "tls",
            "tlsSettings": {"serverName": "front.example.com", "alpn": ["h2"], "fingerprint": "chrome"},
            "masqueSettings": {"host": "h.example.com", "path": "/masque", "user": "alice", "pass": "s3cret"},
        },
    }


def test_masque_alpn_defaults_to_h2_even_if_the_profile_has_none():
    p = masque()
    p.tls.alpn = []
    assert stream_of(p)["tlsSettings"]["alpn"] == ["h2"]


def test_masque_explicit_alpn_selects_http3():
    p = parse_link("masque://m.example.com:443?sni=s&alpn=h3")
    assert stream_of(p)["tlsSettings"]["alpn"] == ["h3"]


def test_masque_remote_dns_headers_and_finalmask():
    p = parse_link(
        "masque://m.example.com:443?sni=s&dns=1.1.1.1,8.8.8.8"
        "&headers=%7B%22X-Token%22%3A%22abc%22%7D&fm=%7B%22tcp%22%3A%5B%7B%22type%22%3A%22fragment%22%7D%5D%7D"
    )
    out = outbound_of(p)
    assert out["settings"]["remoteDNS"] == ["1.1.1.1", "8.8.8.8"]
    assert out["streamSettings"]["masqueSettings"]["headers"] == {"X-Token": "abc"}
    assert out["streamSettings"]["finalmask"] == {"tcp": [{"type": "fragment"}]}
    assert "user" not in out["streamSettings"]["masqueSettings"]


def test_masque_with_warp_has_no_user_or_pass():
    warp = "%7B%22privateKey%22%3A%22PRIV%22%2C%22publicKey%22%3A%22PUB%22%2C%22address%22%3A%5B%221.2.3.4%2F32%22%5D%7D"
    out = outbound_of(parse_link("masque://m.example.com:443?sni=s&warp=" + warp))
    masque_settings = out["streamSettings"]["masqueSettings"]
    assert masque_settings["warp"]["privateKey"] == "PRIV"
    assert "user" not in masque_settings and "pass" not in masque_settings


def test_masque_user_and_warp_together_are_rejected_at_generation_too():
    p = masque()
    p.extra["warp"] = {"privateKey": "a", "publicKey": "b", "address": ["1.2.3.4/32"]}
    with pytest.raises(ProfileValidationError, match="warp"):
        generate_config(p, GLOBAL, 1, 2)


def test_masque_inbounds_still_follow_listen_address_and_auth():
    config = generate_config(masque(), GLOBAL, 10808, 10809, "172.18.0.1", ProxyAuth("u", "p"))
    assert [i["listen"] for i in config["inbounds"]] == ["172.18.0.1", "172.18.0.1"]
    assert config["inbounds"][1]["settings"]["accounts"] == [{"user": "u", "pass": "p"}]


# ---- pre-flight predicate -------------------------------------------------------


def test_needs_preflight_only_for_raw_masque_and_newer_core_features():
    assert needs_preflight(masque())
    assert needs_preflight(Profile(name="r", protocol=Protocol.RAW_XRAY, raw_config={"outbounds": []}))
    assert needs_preflight(parse_link(LINKS[0]))  # finalmask
    assert needs_preflight(parse_link(LINKS[1]))  # ECH
    assert needs_preflight(parse_link(link_with(lambda q, _: q.get("type") == "xhttp")))
    assert needs_preflight(parse_link(link_with(lambda q, _: q.get("encryption", "").startswith("mlkem"))))
    assert not needs_preflight(parse_link(LINKS[2]))  # plain ws+tls
    assert not needs_preflight(
        Profile(name="s", protocol=Protocol.SHADOWSOCKS, server="s", port=1, method="aes-128-gcm", password="p")
    )
