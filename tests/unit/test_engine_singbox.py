from __future__ import annotations

from v2rm.engines import engine_for_protocol
from v2rm.engines.singbox.generate import generate_config
from v2rm.models.enums import EngineKind, Protocol, SecurityKind
from v2rm.models.profile import Profile, TlsSettings
from v2rm.routing.presets import BYPASS_IR, GLOBAL


def test_singbox_inbounds_bind_localhost_only():
    p = Profile(name="T", protocol=Protocol.TROJAN, server="t.example.com", port=443, password="pw")
    config = generate_config(p, GLOBAL, 10808, 10809)
    for inbound in config["inbounds"]:
        assert inbound["listen"] == "127.0.0.1"
    assert {i["type"] for i in config["inbounds"]} == {"socks", "http"}


def test_singbox_hysteria2_outbound():
    p = Profile(
        name="H2",
        protocol=Protocol.HYSTERIA2,
        server="h.example.com",
        port=443,
        password="pw",
        tls=TlsSettings(security=SecurityKind.TLS, sni="h.example.com"),
        extra={"obfs": "salamander", "obfs_password": "opw"},
    )
    config = generate_config(p, GLOBAL, 10808, 10809)
    proxy = config["outbounds"][0]
    assert proxy["type"] == "hysteria2"
    assert proxy["password"] == "pw"
    assert proxy["obfs"] == {"type": "salamander", "password": "opw"}
    assert proxy["tls"]["enabled"] is True
    assert proxy["tls"]["server_name"] == "h.example.com"


def test_singbox_tuic_outbound():
    p = Profile(
        name="TU", protocol=Protocol.TUIC, server="tu.example.com", port=443,
        uuid="u1", password="pw", congestion_control="bbr",
    )
    config = generate_config(p, GLOBAL, 10808, 10809)
    proxy = config["outbounds"][0]
    assert proxy["type"] == "tuic"
    assert proxy["congestion_control"] == "bbr"
    assert proxy["tls"]["enabled"] is True  # TLS is mandatory even with no explicit tls settings


def test_singbox_route_final_is_proxy():
    p = Profile(name="T", protocol=Protocol.TROJAN, server="t.example.com", port=443, password="pw")
    config = generate_config(p, GLOBAL, 10808, 10809)
    assert config["route"]["final"] == "proxy"


def test_singbox_bypass_ir_produces_rule_sets():
    p = Profile(name="T", protocol=Protocol.TROJAN, server="t.example.com", port=443, password="pw")
    config = generate_config(p, BYPASS_IR, 10808, 10809)
    tags = {rs["tag"] for rs in config["route"]["rule_set"]}
    assert "geoip-private" in tags
    assert "geoip-ir" in tags
    assert "geosite-category-ir" in tags


def test_engine_for_protocol_prefers_xray_falls_back_to_singbox():
    assert engine_for_protocol(Protocol.VLESS) == EngineKind.XRAY
    assert engine_for_protocol(Protocol.SHADOWSOCKS) == EngineKind.XRAY
    assert engine_for_protocol(Protocol.HYSTERIA2) == EngineKind.SINGBOX
    assert engine_for_protocol(Protocol.TUIC) == EngineKind.SINGBOX
