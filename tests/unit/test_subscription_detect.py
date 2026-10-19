from __future__ import annotations

import base64
import json

from tests.helpers import free_links, read_fixture
from v2rm.models.enums import SubscriptionFormat
from v2rm.subscription.detect import detect_format
from v2rm.subscription.meta import parse_meta, strip_comment_lines


def test_detect_xray_json_array_from_the_real_serverless_body():
    assert detect_format(read_fixture("serverless_subscription.json")) == SubscriptionFormat.XRAY_JSON


def test_detect_xray_json_single_object():
    assert detect_format(json.dumps({"remarks": "x", "outbounds": []})) == SubscriptionFormat.XRAY_JSON


def test_detect_xray_json_with_a_bom():
    assert detect_format("﻿" + json.dumps([{"outbounds": []}])) == SubscriptionFormat.XRAY_JSON


def test_json_that_is_not_an_xray_config_is_not_xray_json():
    assert detect_format(json.dumps({"proxies": "not a list"})) != SubscriptionFormat.XRAY_JSON
    assert detect_format("[]") != SubscriptionFormat.XRAY_JSON
    assert detect_format(json.dumps([{"remarks": "no outbounds"}])) != SubscriptionFormat.XRAY_JSON


def test_real_free_configs_sample_with_its_header_comments_is_a_plain_list():
    # The header block is full of "https://..." comment lines.
    assert detect_format(read_fixture("free_configs_sample.txt")) == SubscriptionFormat.PLAIN_LIST


def test_base64_body_with_a_comment_header_is_still_base64():
    # A comment header containing URLs must not make an encoded body look like a link list.
    encoded = base64.b64encode("\n".join(free_links()).encode()).decode()
    body = "#profile-title: Encoded\n#profile-web-page-url: https://example.com/x\n" + encoded
    assert detect_format(body) == SubscriptionFormat.BASE64_LIST


def test_base64_is_not_mistaken_for_json():
    encoded = base64.b64encode(json.dumps([{"outbounds": []}]).encode()).decode()
    assert detect_format(encoded) == SubscriptionFormat.BASE64_LIST


def test_strip_comment_lines():
    text = "#a: b\n  # indented comment\nvless://x\n#tail\ntrojan://y"
    assert strip_comment_lines(text) == "vless://x\ntrojan://y"


def test_parse_meta_from_the_real_header_block():
    meta = parse_meta(read_fixture("free_configs_sample.txt"))
    assert meta.title == "Free-Configs"
    assert meta.update_interval_hours == 1.0
    assert meta.web_page_url == "https://github.com/patterniha/Free-Configs"


def test_parse_meta_base64_title_and_fractional_interval():
    title = base64.b64encode("My Provider — تست".encode()).decode()
    meta = parse_meta(f"#profile-title: base64:{title}\n#profile-update-interval: 0.5\nvless://x")
    assert meta.title == "My Provider — تست"
    assert meta.update_interval_hours == 0.5


def test_parse_meta_ignores_garbage_and_non_positive_intervals():
    assert parse_meta("#profile-update-interval: soon").update_interval_hours is None
    assert parse_meta("#profile-update-interval: 0").update_interval_hours is None
    assert parse_meta("#profile-update-interval: -3").update_interval_hours is None
    assert parse_meta("no headers here").title is None
    assert parse_meta("# profile-title:").title is None


def test_parse_meta_is_case_insensitive_and_tolerates_spacing():
    meta = parse_meta("#  Profile-Title :   Spaced  \n#PROFILE-UPDATE-INTERVAL: 6")
    assert meta.title == "Spaced"
    assert meta.update_interval_hours == 6.0


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
