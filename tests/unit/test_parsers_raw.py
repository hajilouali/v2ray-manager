from __future__ import annotations

import json

import pytest

from tests.helpers import free_links, load_json_fixture, read_fixture
from v2rm.errors import ParseError
from v2rm.models.enums import Protocol
from v2rm.parsers import to_link
from v2rm.parsers.raw import (
    is_raw_config,
    is_xray_json_body,
    parse_xray_json,
    profile_from_config,
    raw_profile_name,
    validate_raw_config,
)


def test_serverless_fixture_becomes_two_raw_profiles():
    profiles, errors = parse_xray_json(read_fixture("serverless_subscription.json"))
    assert not errors
    assert [p.name for p in profiles] == ["Serverless-v52-fragA", "Serverless-v52-fragB"]
    for p in profiles:
        assert p.protocol == Protocol.RAW_XRAY
        assert p.is_raw
        assert p.server == "" and p.port == 0
        assert p.raw_config["version"] == {"min": "26.6.27"}
        assert p.raw_config["inbounds"][0]["protocol"] == "mixed"


def test_raw_profile_keeps_the_original_config_byte_for_byte_structurally():
    original = load_json_fixture("serverless_subscription.json")
    profiles, _ = parse_xray_json(read_fixture("serverless_subscription.json"))
    assert [p.raw_config for p in profiles] == original


def test_serverless_identity_keys_follow_remarks():
    profiles, _ = parse_xray_json(read_fixture("serverless_subscription.json"))
    assert [p.identity_key() for p in profiles] == [
        ("raw-xray", "Serverless-v52-fragA"),
        ("raw-xray", "Serverless-v52-fragB"),
    ]


def test_single_config_object_is_accepted():
    cfg = {"remarks": "solo", "outbounds": [{"protocol": "direct", "tag": "d"}]}
    profiles, errors = parse_xray_json(json.dumps(cfg))
    assert len(profiles) == 1 and not errors
    assert profiles[0].name == "solo"


def test_name_falls_back_to_a_content_hash_without_remarks():
    cfg = {"outbounds": [{"protocol": "direct", "tag": "d"}]}
    name = raw_profile_name(cfg)
    assert name.startswith("raw-xray-") and len(name) == len("raw-xray-") + 8
    assert raw_profile_name(cfg) == name  # deterministic


def test_array_with_an_invalid_item_imports_the_rest_and_reports_it():
    text = json.dumps(
        [
            {"remarks": "good", "outbounds": []},
            {"remarks": "no-outbounds"},
            "not an object",
            {"remarks": "good2", "outbounds": [{"protocol": "block"}]},
        ]
    )
    profiles, errors = parse_xray_json(text)
    assert [p.name for p in profiles] == ["good", "good2"]
    assert [e[0] for e in errors] == ["no-outbounds", "item 3"]


def test_invalid_json_raises():
    with pytest.raises(ParseError, match="JSON"):
        parse_xray_json("{not json")


def test_empty_array_raises():
    with pytest.raises(ParseError, match="empty"):
        parse_xray_json("[]")


def test_a_leading_bom_is_tolerated():
    profiles, _ = parse_xray_json("﻿" + json.dumps({"remarks": "bom", "outbounds": []}))
    assert profiles[0].name == "bom"


def test_validate_raw_config_requires_an_outbounds_list():
    assert validate_raw_config({"outbounds": []}) == {"outbounds": []}
    with pytest.raises(ParseError):
        validate_raw_config({"outbounds": "x"})
    with pytest.raises(ParseError):
        validate_raw_config([])
    assert is_raw_config({"outbounds": []})
    assert not is_raw_config({"remarks": "x"})


def test_profile_from_config_deep_copies():
    cfg = {"remarks": "r", "outbounds": [{"tag": "a"}]}
    p = profile_from_config(cfg)
    cfg["outbounds"].append({"tag": "b"})
    assert len(p.raw_config["outbounds"]) == 1


def test_is_xray_json_body():
    assert is_xray_json_body(read_fixture("serverless_subscription.json"))  # array of configs
    assert is_xray_json_body('{"outbounds": []}')  # single object
    assert not is_xray_json_body("[]")
    assert not is_xray_json_body('[{"remarks": "x"}]')  # items aren't configs
    assert not is_xray_json_body('{"proxies": []}')  # a Clash-ish object
    assert not is_xray_json_body(read_fixture("free_configs_sample.txt"))
    assert not is_xray_json_body("")
    assert not is_xray_json_body("dmxlc3M6Ly9hYmNkZWY=")  # base64 isn't fed to the JSON parser


def test_raw_profile_has_no_share_link():
    profiles, _ = parse_xray_json(read_fixture("serverless_subscription.json"))
    with pytest.raises(ParseError, match="no share link"):
        to_link(profiles[0])


def test_link_list_is_not_mistaken_for_json():
    assert not is_xray_json_body("\n".join(free_links()))
