from __future__ import annotations

import pytest

from v2rm.errors import ParseError
from v2rm.models.enums import Protocol, SecurityKind, TransportKind
from v2rm.subscription.clash_yaml import parse_clash_yaml

YAML_TEXT = """
proxies:
  - name: "VmessWs"
    type: vmess
    server: v.example.com
    port: 443
    uuid: uuid-1
    alterId: 0
    cipher: auto
    tls: true
    network: ws
    servername: v.example.com
    ws-opts:
      path: /ray
      headers:
        Host: v.example.com
  - name: "VlessReality"
    type: vless
    server: r.example.com
    port: 443
    uuid: uuid-2
    flow: xtls-rprx-vision
    tls: true
    servername: hide.example.com
    client-fingerprint: chrome
    reality-opts:
      public-key: pubkey123
      short-id: ab12
  - name: "TrojanNode"
    type: trojan
    server: t.example.com
    port: 443
    password: pw123
    sni: t.example.com
  - name: "SSNode"
    type: ss
    server: s.example.com
    port: 8388
    cipher: aes-256-gcm
    password: sspw
  - name: "Hy2Node"
    type: hysteria2
    server: h.example.com
    port: 443
    password: hy2pw
    obfs: salamander
    obfs-password: obfspw
  - name: "TuicNode"
    type: tuic
    server: tu.example.com
    port: 443
    uuid: uuid-3
    password: tuicpw
    congestion-controller: bbr
  - name: "BadNode"
    type: unknown-protocol
    server: x.example.com
    port: 1
"""


def test_parse_clash_yaml_all_types():
    profiles, errors = parse_clash_yaml(YAML_TEXT)
    by_name = {p.name: p for p in profiles}

    assert len(errors) == 1
    assert errors[0][0] == "BadNode"

    vmess = by_name["VmessWs"]
    assert vmess.protocol == Protocol.VMESS
    assert vmess.transport.network == TransportKind.WS
    assert vmess.transport.path == "/ray"
    assert vmess.transport.host == "v.example.com"
    assert vmess.tls.security == SecurityKind.TLS

    vless = by_name["VlessReality"]
    assert vless.protocol == Protocol.VLESS
    assert vless.flow == "xtls-rprx-vision"
    assert vless.tls.security == SecurityKind.REALITY
    assert vless.tls.reality.public_key == "pubkey123"
    assert vless.tls.fingerprint == "chrome"

    trojan = by_name["TrojanNode"]
    assert trojan.protocol == Protocol.TROJAN
    assert trojan.password == "pw123"
    assert trojan.tls.security == SecurityKind.TLS

    ss = by_name["SSNode"]
    assert ss.protocol == Protocol.SHADOWSOCKS
    assert ss.method == "aes-256-gcm"
    assert ss.password == "sspw"

    hy2 = by_name["Hy2Node"]
    assert hy2.protocol == Protocol.HYSTERIA2
    assert hy2.extra["obfs"] == "salamander"
    assert hy2.extra["obfs_password"] == "obfspw"

    tuic = by_name["TuicNode"]
    assert tuic.protocol == Protocol.TUIC
    assert tuic.congestion_control == "bbr"


def test_parse_clash_yaml_missing_proxies_key_raises():
    with pytest.raises(ParseError):
        parse_clash_yaml("not_proxies: []")


def test_parse_clash_yaml_invalid_yaml_raises():
    with pytest.raises(ParseError):
        parse_clash_yaml("proxies: [this is not: valid: yaml: at: all")
