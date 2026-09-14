from __future__ import annotations

import base64

from v2rm.models.enums import SubscriptionFormat
from v2rm.subscription.detect import detect_format


def test_detect_plain_list():
    text = "trojan://pw@a.example.com:443#A\nvless://uuid@b.example.com:443?security=tls#B"
    assert detect_format(text) == SubscriptionFormat.PLAIN_LIST


def test_detect_base64_list():
    raw = "trojan://pw@a.example.com:443#A\nvless://uuid@b.example.com:443?security=tls#B"
    encoded = base64.b64encode(raw.encode()).decode()
    assert detect_format(encoded) == SubscriptionFormat.BASE64_LIST


def test_detect_clash_yaml():
    text = (
        "proxies:\n"
        "  - name: node1\n"
        "    type: trojan\n"
        "    server: a.example.com\n"
        "    port: 443\n"
        "    password: pw\n"
    )
    assert detect_format(text) == SubscriptionFormat.CLASH_YAML


def test_detect_empty_defaults_to_plain_list():
    assert detect_format("") == SubscriptionFormat.PLAIN_LIST


def test_detect_yaml_without_proxies_key_is_not_clash():
    assert detect_format("foo: bar\nbaz: 1\n") == SubscriptionFormat.PLAIN_LIST
