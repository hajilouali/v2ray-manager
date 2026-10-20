"""Dialling a profile's connection through another proxy (a hop of a chain), and the "front"."""

from __future__ import annotations

import pytest

from tests.helpers import serverless_profiles
from v2rm.engines import generate_config
from v2rm.engines.xray.generate import UPSTREAM_TAG, generate_front_config
from v2rm.errors import UnsupportedFeatureError, UnsupportedProtocolError
from v2rm.models.auth import ProxyAuth
from v2rm.models.enums import EngineKind, Protocol
from v2rm.models.profile import Profile
from v2rm.net.proxy_url import parse_proxy_url
from v2rm.parsers import parse_link
from v2rm.routing.presets import BYPASS_IR, GLOBAL

XRAY, SINGBOX = EngineKind.XRAY, EngineKind.SINGBOX
UPSTREAM = parse_proxy_url("socks5://127.0.0.1:41000")


def trojan() -> Profile:
    return Profile(name="t", protocol=Protocol.TROJAN, server="t.example.com", port=443, password="pw")


def vless_ws_tls() -> Profile:
    return parse_link("vless://11111111-2222-3333-4444-555555555555@v.example.com:443?type=ws&security=tls&sni=v.example.com&path=%2Fw#v")


def hysteria2() -> Profile:
    return Profile(name="h", protocol=Protocol.HYSTERIA2, server="h.example.com", port=443, password="pw")


def build(engine, profile, upstream=None, **kw):
    return generate_config(engine, profile, GLOBAL, 10808, 10809, upstream=upstream, **kw)


def outbound(config, tag):
    return next(o for o in config["outbounds"] if o.get("tag") == tag)


# ---- Xray ---------------------------------------------------------------------------------------


def test_without_an_upstream_nothing_changes():
    config = build(XRAY, trojan())
    assert [o["tag"] for o in config["outbounds"]] == ["proxy", "direct", "block"]
    assert "streamSettings" not in outbound(config, "proxy")


def test_xray_dials_the_server_through_the_previous_hops_socks_port():
    config = build(XRAY, trojan(), UPSTREAM)
    proxy = outbound(config, "proxy")
    assert proxy["streamSettings"]["sockopt"]["dialerProxy"] == UPSTREAM_TAG
    hop = outbound(config, UPSTREAM_TAG)
    assert hop["protocol"] == "socks"
    assert hop["settings"]["servers"] == [{"address": "127.0.0.1", "port": 41000}]


def test_the_dialer_proxy_is_added_beside_existing_stream_settings():
    config = build(XRAY, vless_ws_tls(), UPSTREAM)
    stream = outbound(config, "proxy")["streamSettings"]
    assert stream["network"] == "ws" and stream["security"] == "tls"
    assert stream["sockopt"] == {"dialerProxy": UPSTREAM_TAG}


def test_credentials_of_the_previous_hop_go_to_its_outbound():
    config = build(XRAY, trojan(), parse_proxy_url("socks5://al:pw@10.0.0.2:1080"))
    server = outbound(config, UPSTREAM_TAG)["settings"]["servers"][0]
    assert server["users"] == [{"user": "al", "pass": "pw"}]


def test_an_http_proxy_hop_becomes_an_http_outbound():
    config = build(XRAY, trojan(), parse_proxy_url("http://proxy.example:8080"))
    assert outbound(config, UPSTREAM_TAG)["protocol"] == "http"


def test_a_raw_config_cannot_be_dialled_through_another_hop():
    with pytest.raises(UnsupportedFeatureError, match="first hop"):
        build(XRAY, serverless_profiles()[0], UPSTREAM)


def test_the_listeners_and_routing_of_a_chained_hop_are_the_normal_ones():
    config = build(XRAY, trojan(), UPSTREAM, listen_address="127.0.0.1", auth=ProxyAuth("u", "p"))
    assert [i["port"] for i in config["inbounds"]] == [10808, 10809]
    assert config["routing"]["rules"][-1]["outboundTag"] == "proxy"


# ---- sing-box -----------------------------------------------------------------------------------


def test_singbox_uses_a_detour():
    config = build(SINGBOX, hysteria2(), UPSTREAM)
    assert outbound(config, "proxy")["detour"] == "v2rm-upstream"
    hop = outbound(config, "v2rm-upstream")
    assert (hop["type"], hop["server"], hop["server_port"], hop["version"]) == ("socks", "127.0.0.1", 41000, "5")


def test_singbox_hop_credentials_and_http_kind():
    config = build(SINGBOX, hysteria2(), parse_proxy_url("socks5://al:pw@10.0.0.2:1080"))
    hop = outbound(config, "v2rm-upstream")
    assert (hop["username"], hop["password"]) == ("al", "pw")
    http = outbound(build(SINGBOX, hysteria2(), parse_proxy_url("http://p.example:8080")), "v2rm-upstream")
    assert http["type"] == "http" and "version" not in http


def test_singbox_without_an_upstream_has_no_detour():
    assert "detour" not in outbound(build(SINGBOX, hysteria2()), "proxy")


# ---- dispatch -----------------------------------------------------------------------------------


def test_aether_has_no_config_file():
    with pytest.raises(UnsupportedProtocolError, match="environment"):
        generate_config(EngineKind.AETHER, trojan(), GLOBAL, 1, 2)


# ---- the front ----------------------------------------------------------------------------------


def front(route=GLOBAL, auth=None, listen="127.0.0.1", backend="socks5://127.0.0.1:41000"):
    return generate_front_config(route, 10808, 10809, parse_proxy_url(backend), listen_address=listen, auth=auth)


def test_the_front_has_v2rms_listeners_and_sends_everything_to_the_backend():
    config = front(listen="172.17.0.1")
    assert [(i["protocol"], i["listen"], i["port"]) for i in config["inbounds"]] == [
        ("socks", "172.17.0.1", 10808),
        ("http", "172.17.0.1", 10809),
    ]
    proxy = outbound(config, "proxy")
    assert proxy["protocol"] == "socks"
    assert proxy["settings"]["servers"] == [{"address": "127.0.0.1", "port": 41000}]
    assert config["routing"]["rules"] == [{"type": "field", "outboundTag": "proxy", "port": "0-65535"}]


def test_the_front_carries_the_login_on_both_listeners():
    config = front(auth=ProxyAuth("user", "pw"))
    socks, http = config["inbounds"]
    assert socks["settings"]["auth"] == "password"
    assert socks["settings"]["accounts"] == [{"user": "user", "pass": "pw"}]
    assert http["settings"]["accounts"] == [{"user": "user", "pass": "pw"}]


def test_the_front_applies_the_route_preset():
    rules = front(route=BYPASS_IR)["routing"]["rules"]
    assert any(r.get("outboundTag") == "direct" and "geoip:ir" in r.get("ip", []) for r in rules)
    assert rules[-1]["outboundTag"] == "proxy"
