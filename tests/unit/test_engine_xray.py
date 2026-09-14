from __future__ import annotations

import pytest

from v2rm.engines.xray.generate import generate_config
from v2rm.errors import UnsupportedProtocolError
from v2rm.models.enums import Protocol, SecurityKind, TransportKind
from v2rm.models.profile import Profile, RealitySettings, TlsSettings, TransportSettings
from v2rm.routing.presets import GLOBAL


def make_vless_reality() -> Profile:
    return Profile(
        name="Reality",
        protocol=Protocol.VLESS,
        server="r.example.com",
        port=443,
        uuid="uuid-1",
        flow="xtls-rprx-vision",
        tls=TlsSettings(
            security=SecurityKind.REALITY,
            sni="hide.example.com",
            fingerprint="chrome",
            reality=RealitySettings(public_key="pub", short_id="ab"),
        ),
    )


def test_xray_inbounds_bind_localhost_only_by_default():
    config = generate_config(make_vless_reality(), GLOBAL, 10808, 10809)
    for inbound in config["inbounds"]:
        assert inbound["listen"] == "127.0.0.1"
    assert {i["port"] for i in config["inbounds"]} == {10808, 10809}


def test_xray_inbounds_respect_custom_listen_address():
    config = generate_config(make_vless_reality(), GLOBAL, 10808, 10809, listen_address="172.17.0.1")
    for inbound in config["inbounds"]:
        assert inbound["listen"] == "172.17.0.1"


def test_xray_vless_reality_outbound_shape():
    config = generate_config(make_vless_reality(), GLOBAL, 10808, 10809)
    proxy = config["outbounds"][0]
    assert proxy["protocol"] == "vless"
    user = proxy["settings"]["vnext"][0]["users"][0]
    assert user["id"] == "uuid-1"
    assert user["flow"] == "xtls-rprx-vision"
    assert user["encryption"] == "none"
    assert proxy["streamSettings"]["security"] == "reality"
    assert proxy["streamSettings"]["realitySettings"]["publicKey"] == "pub"


def test_xray_has_direct_and_block_outbounds():
    config = generate_config(make_vless_reality(), GLOBAL, 10808, 10809)
    tags = {o["tag"] for o in config["outbounds"]}
    assert {"proxy", "direct", "block"} <= tags


def test_xray_shadowsocks_outbound_has_no_stream_settings():
    p = Profile(
        name="SS", protocol=Protocol.SHADOWSOCKS, server="s.example.com", port=8388,
        method="aes-256-gcm", password="pw",
    )
    config = generate_config(p, GLOBAL, 10808, 10809)
    proxy = config["outbounds"][0]
    assert proxy["protocol"] == "shadowsocks"
    server = proxy["settings"]["servers"][0]
    assert server["method"] == "aes-256-gcm"
    assert server["password"] == "pw"
    assert "streamSettings" not in proxy


def test_xray_vmess_ws_stream_settings():
    p = Profile(
        name="V",
        protocol=Protocol.VMESS,
        server="v.example.com",
        port=443,
        uuid="u1",
        alter_id=0,
        method="auto",
        transport=TransportSettings(network=TransportKind.WS, path="/ray", host="v.example.com"),
        tls=TlsSettings(security=SecurityKind.TLS, sni="v.example.com"),
    )
    config = generate_config(p, GLOBAL, 10808, 10809)
    stream = config["outbounds"][0]["streamSettings"]
    assert stream["network"] == "ws"
    assert stream["wsSettings"]["path"] == "/ray"
    assert stream["security"] == "tls"
    assert stream["tlsSettings"]["serverName"] == "v.example.com"


def test_xray_rejects_hysteria2():
    p = Profile(name="H", protocol=Protocol.HYSTERIA2, server="h.example.com", port=443, password="pw")
    with pytest.raises(UnsupportedProtocolError):
        generate_config(p, GLOBAL, 10808, 10809)
