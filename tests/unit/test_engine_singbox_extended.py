from __future__ import annotations

import pytest

from tests.helpers import free_links, link_with
from v2rm.engines.singbox.generate import generate_config
from v2rm.errors import UnsupportedFeatureError, UnsupportedProtocolError
from v2rm.models.auth import ProxyAuth
from v2rm.models.enums import Protocol, SecurityKind, TransportKind
from v2rm.models.profile import Profile, TlsSettings, TransportSettings
from v2rm.parsers import parse_link
from v2rm.routing.presets import GLOBAL

LINKS = free_links()


def outbound_of(profile: Profile) -> dict:
    return generate_config(profile, GLOBAL, 10808, 10809)["outbounds"][0]


def vless(**overrides) -> Profile:
    fields = {
        "name": "v", "protocol": Protocol.VLESS, "server": "s.example.com", "port": 443, "uuid": "u",
        "tls": TlsSettings(security=SecurityKind.TLS, sni="s.example.com"),
    }
    fields.update(overrides)
    return Profile(**fields)


# ---- profiles sing-box can't run at all ---------------------------------------


@pytest.mark.parametrize(
    "profile",
    [
        Profile(name="r", protocol=Protocol.RAW_XRAY, raw_config={"outbounds": []}),
        parse_link("masque://m.example.com:443?sni=s"),
    ],
    ids=["raw", "masque"],
)
def test_raw_and_masque_profiles_point_the_user_at_xray(profile):
    with pytest.raises(UnsupportedProtocolError, match="Xray-core"):
        generate_config(profile, GLOBAL, 1, 2)


# ---- options with no sing-box equivalent are reported, never dropped ----------


@pytest.mark.parametrize(
    ("link", "expected"),
    [
        (LINKS[0], ["finalmask", "'unsafe' TLS fingerprint"]),
        (LINKS[1], ["ECH"]),
        (link_with(lambda q, _: q.get("encryption", "").startswith("mlkem")), ["post-quantum"]),
        (link_with(lambda q, _: q.get("type") == "xhttp"), ["'xhttp' transport"]),
    ],
    ids=["finalmask+unsafe-fp", "ech", "mlkem", "xhttp"],
)
def test_real_links_using_xray_only_features_raise_a_clear_error(link, expected):
    with pytest.raises(UnsupportedFeatureError) as err:
        generate_config(parse_link(link), GLOBAL, 1, 2)
    message = str(err.value)
    for fragment in expected:
        assert fragment in message
    assert "Use Xray-core" in message and "v2rm core use xray" in message


def test_kcp_transport_is_reported():
    p = vless(transport=TransportSettings(network=TransportKind.KCP))
    with pytest.raises(UnsupportedFeatureError, match="'kcp' transport"):
        generate_config(p, GLOBAL, 1, 2)


def test_all_the_problems_are_listed_together_not_one_at_a_time():
    with pytest.raises(UnsupportedFeatureError) as err:
        generate_config(parse_link(LINKS[4]), GLOBAL, 1, 2)  # unsafe fp + finalmask + ECH
    message = str(err.value)
    assert "finalmask" in message and "ECH" in message and "'unsafe' TLS fingerprint" in message


def test_a_link_using_only_expressible_options_generates_normally():
    out = outbound_of(parse_link(LINKS[2]))
    assert out["type"] == "vless"
    assert out["server"] == "2a06:98c1:3101::6812:202f"
    assert out["transport"] == {
        "type": "ws",
        "path": "/drsukitgreiusweqa9otrh983",
        "headers": {"Host": "server5.9966338.xyz"},
    }
    assert out["tls"] == {
        "enabled": True,
        "server_name": "server5.9966338.xyz",
        "alpn": ["http/1.1"],
        "utls": {"enabled": True, "fingerprint": "chrome"},
    }


# ---- what *is* mapped ------------------------------------------------------------


def test_cipher_suites_become_a_list():
    p = vless(tls=TlsSettings(
        security=SecurityKind.TLS, sni="s", fingerprint="chrome",
        cipher_suites="TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256",
    ))
    assert outbound_of(p)["tls"]["cipher_suites"] == ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"]


def test_fingerprint_names_are_lowercased_for_utls():
    p = vless(tls=TlsSettings(security=SecurityKind.TLS, sni="s", fingerprint="Chrome"))
    assert outbound_of(p)["tls"]["utls"] == {"enabled": True, "fingerprint": "chrome"}


def test_ws_headers_are_kept_and_the_host_param_wins_over_a_host_header():
    p = vless(transport=TransportSettings(
        network=TransportKind.WS, path="/p", host="explicit.example.com",
        headers={"Host": "header.example.com", "X-Token": "abc"},
    ))
    assert outbound_of(p)["transport"]["headers"] == {"X-Token": "abc", "Host": "explicit.example.com"}


def test_ws_host_header_alone_is_used_as_the_host():
    p = vless(transport=TransportSettings(network=TransportKind.WS, path="/p", headers={"Host": "header.example.com"}))
    assert outbound_of(p)["transport"]["headers"] == {"Host": "header.example.com"}


def test_httpupgrade_gets_host_and_extra_headers():
    p = vless(transport=TransportSettings(
        network=TransportKind.HTTPUPGRADE, path="/u", headers={"Host": "h.example.com", "X-A": "1"},
    ))
    assert outbound_of(p)["transport"] == {
        "type": "httpupgrade", "path": "/u", "host": "h.example.com", "headers": {"X-A": "1"},
    }


@pytest.mark.parametrize(
    ("value", "expected"),
    [("xudp", "xudp"), ("XUDP", "xudp"), ("packet", "packetaddr"), ("packetaddr", "packetaddr"), ("", None), ("none", None)],
)
def test_packet_encoding_is_mapped_where_sing_box_has_an_equivalent(value, expected):
    for protocol, extra in ((Protocol.VLESS, {}), (Protocol.VMESS, {})):
        p = vless(protocol=protocol, packet_encoding=value, **extra)
        assert outbound_of(p).get("packet_encoding") == expected


def test_packet_encoding_from_a_real_link_reaches_the_outbound():
    p = parse_link(link_with(lambda q, _: q.get("packetEncoding")))
    assert p.packet_encoding == "xudp"
    # The real link also uses Xray-only options (unsafe fingerprint, finalmask);
    # drop those so what's left is exactly what sing-box can run.
    p.tls.fingerprint, p.tls.cipher_suites, p.transport.finalmask = "chrome", "", {}
    assert outbound_of(p)["packet_encoding"] == "xudp"


def test_allow_insecure_is_still_supported_here():
    p = vless(tls=TlsSettings(security=SecurityKind.TLS, sni="s", allow_insecure=True))
    assert outbound_of(p)["tls"]["insecure"] is True


# ---- inbounds ----------------------------------------------------------------------


def test_auth_becomes_users_on_both_inbounds():
    config = generate_config(parse_link(LINKS[2]), GLOBAL, 10808, 10809, "172.18.0.1", ProxyAuth("demo", "demo-pass"))
    for inbound in config["inbounds"]:
        assert inbound["listen"] == "172.18.0.1"
        assert inbound["users"] == [{"username": "demo", "password": "demo-pass"}]


def test_no_auth_means_no_users_key():
    config = generate_config(parse_link(LINKS[2]), GLOBAL, 10808, 10809)
    assert all("users" not in inbound for inbound in config["inbounds"])
