from __future__ import annotations

import base64
import json

import pytest

from v2rm.errors import ParseError
from v2rm.models.enums import Protocol, SecurityKind, TransportKind
from v2rm.parsers import parse_link, parse_links, to_link


def test_parse_vmess_ws_tls():
    payload = {
        "v": "2",
        "ps": "MyServer",
        "add": "vmess.example.com",
        "port": "443",
        "id": "b831381d-6324-4d53-ad4f-8cda48b30811",
        "aid": "0",
        "scy": "auto",
        "net": "ws",
        "type": "none",
        "host": "vmess.example.com",
        "path": "/ray",
        "tls": "tls",
        "sni": "vmess.example.com",
        "alpn": "h2,http/1.1",
        "fp": "chrome",
    }
    link = "vmess://" + base64.b64encode(json.dumps(payload).encode()).decode()

    p = parse_link(link)

    assert p.protocol == Protocol.VMESS
    assert p.name == "MyServer"
    assert p.server == "vmess.example.com"
    assert p.port == 443
    assert p.uuid == "b831381d-6324-4d53-ad4f-8cda48b30811"
    assert p.transport.network == TransportKind.WS
    assert p.transport.path == "/ray"
    assert p.tls.security == SecurityKind.TLS
    assert p.tls.sni == "vmess.example.com"
    assert p.tls.alpn == ["h2", "http/1.1"]


def test_vmess_round_trip_through_to_link():
    payload = {
        "v": "2", "ps": "RT", "add": "a.example.com", "port": "8443", "id": "u-1",
        "aid": "0", "net": "tcp", "tls": "",
    }
    link = "vmess://" + base64.b64encode(json.dumps(payload).encode()).decode()
    p1 = parse_link(link)
    p2 = parse_link(to_link(p1))
    assert p2.server == p1.server
    assert p2.port == p1.port
    assert p2.uuid == p1.uuid
    assert p2.name == p1.name


def test_vmess_grpc_service_name_round_trip():
    payload = {
        "v": "2", "ps": "GrpcNode", "add": "grpc.example.com", "port": "443", "id": "u-2",
        "aid": "0", "net": "grpc", "path": "myServiceName", "tls": "tls",
    }
    link = "vmess://" + base64.b64encode(json.dumps(payload).encode()).decode()
    p = parse_link(link)
    assert p.transport.network == TransportKind.GRPC
    assert p.transport.service_name == "myServiceName"

    p2 = parse_link(to_link(p))
    assert p2.transport.service_name == "myServiceName"


def test_parse_vless_reality():
    link = (
        "vless://11111111-2222-3333-4444-555555555555@reality.example.com:443"
        "?encryption=none&security=reality&sni=hide.example.com&fp=chrome"
        "&pbk=abcDEF123-publickey&sid=deadbeef&spx=%2F&type=tcp&flow=xtls-rprx-vision"
        "#My%20Reality%20Node"
    )
    p = parse_link(link)

    assert p.protocol == Protocol.VLESS
    assert p.name == "My Reality Node"
    assert p.server == "reality.example.com"
    assert p.port == 443
    assert p.uuid == "11111111-2222-3333-4444-555555555555"
    assert p.flow == "xtls-rprx-vision"
    assert p.tls.security == SecurityKind.REALITY
    assert p.tls.reality is not None
    assert p.tls.reality.public_key == "abcDEF123-publickey"
    assert p.tls.reality.short_id == "deadbeef"


def test_vless_round_trip():
    link = (
        "vless://11111111-2222-3333-4444-555555555555@reality.example.com:443"
        "?security=reality&sni=hide.example.com&pbk=pubkey123&sid=ab12&type=ws&path=%2Fpath"
        "#Node"
    )
    p1 = parse_link(link)
    p2 = parse_link(to_link(p1))
    assert p2.uuid == p1.uuid
    assert p2.tls.reality.public_key == p1.tls.reality.public_key
    assert p2.transport.path == p1.transport.path


def test_parse_trojan_ws():
    link = (
        "trojan://sup3rSecret@trojan.example.com:443"
        "?security=tls&type=ws&path=%2Fws&host=trojan.example.com&sni=trojan.example.com"
        "#Trojan%20Node"
    )
    p = parse_link(link)

    assert p.protocol == Protocol.TROJAN
    assert p.password == "sup3rSecret"
    assert p.server == "trojan.example.com"
    assert p.transport.network == TransportKind.WS
    assert p.tls.sni == "trojan.example.com"
    assert p.name == "Trojan Node"


def test_trojan_defaults_to_tls_when_security_omitted():
    p = parse_link("trojan://pw@host.example.com:443#NoSecurityParam")
    assert p.tls.security == SecurityKind.TLS


def test_parse_shadowsocks_sip002():
    userinfo = base64.urlsafe_b64encode(b"aes-256-gcm:s3cret-pass").decode().rstrip("=")
    link = f"ss://{userinfo}@ss.example.com:8388#SS%20Node"
    p = parse_link(link)

    assert p.protocol == Protocol.SHADOWSOCKS
    assert p.method == "aes-256-gcm"
    assert p.password == "s3cret-pass"
    assert p.server == "ss.example.com"
    assert p.port == 8388
    assert p.name == "SS Node"


def test_parse_shadowsocks_legacy_full_base64():
    blob = base64.urlsafe_b64encode(b"chacha20-ietf-poly1305:hunter2@legacy.example.com:8989").decode().rstrip("=")
    link = f"ss://{blob}"
    p = parse_link(link)

    assert p.method == "chacha20-ietf-poly1305"
    assert p.password == "hunter2"
    assert p.server == "legacy.example.com"
    assert p.port == 8989


def test_ss_round_trip():
    userinfo = base64.urlsafe_b64encode(b"aes-128-gcm:pw").decode().rstrip("=")
    link = f"ss://{userinfo}@s.example.com:1234#Node"
    p1 = parse_link(link)
    p2 = parse_link(to_link(p1))
    assert p2.method == p1.method
    assert p2.password == p1.password
    assert p2.server == p1.server
    assert p2.port == p1.port


def test_parse_hysteria2_with_obfs():
    link = (
        "hysteria2://pw123@hy2.example.com:443"
        "?insecure=1&sni=hy2.example.com&obfs=salamander&obfs-password=obfspw#HY2"
    )
    p = parse_link(link)

    assert p.protocol == Protocol.HYSTERIA2
    assert p.password == "pw123"
    assert p.tls.allow_insecure is True
    assert p.extra["obfs"] == "salamander"
    assert p.extra["obfs_password"] == "obfspw"


def test_parse_hysteria2_hy2_scheme():
    p = parse_link("hy2://pw@short.example.com:443#Short")
    assert p.protocol == Protocol.HYSTERIA2
    assert p.server == "short.example.com"


def test_parse_tuic():
    link = "tuic://uuid-abc:pw-def@tuic.example.com:443?congestion_control=bbr&alpn=h3&sni=tuic.example.com#TUIC"
    p = parse_link(link)

    assert p.protocol == Protocol.TUIC
    assert p.uuid == "uuid-abc"
    assert p.password == "pw-def"
    assert p.congestion_control == "bbr"
    assert p.tls.alpn == ["h3"]


def test_tuic_round_trip():
    link = "tuic://uuid-abc:pw-def@tuic.example.com:443?congestion_control=bbr&alpn=h3#TUIC"
    p1 = parse_link(link)
    p2 = parse_link(to_link(p1))
    assert p2.uuid == p1.uuid
    assert p2.password == p1.password
    assert p2.congestion_control == p1.congestion_control


def test_parse_unsupported_scheme():
    with pytest.raises(ParseError):
        parse_link("socks://user:pass@host:1080")


def test_parse_invalid_base64_vmess():
    with pytest.raises(ParseError):
        parse_link("vmess://not-valid-base64!!!")


def test_parse_missing_port():
    with pytest.raises(ParseError):
        parse_link("trojan://pw@host.example.com#NoPort")


def test_parse_links_partial_failure():
    good = "trojan://pw@host.example.com:443#Good"
    bad = "notreal://broken"
    profiles, errors = parse_links(f"{good}\n{bad}\n")

    assert len(profiles) == 1
    assert profiles[0].name == "Good"
    assert len(errors) == 1
    assert errors[0][0] == bad


def test_parse_links_skips_blank_lines_and_comments():
    text = "\n# a comment\ntrojan://pw@host.example.com:443#Only\n\n"
    profiles, errors = parse_links(text)
    assert len(profiles) == 1
    assert not errors
