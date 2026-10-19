from __future__ import annotations

import copy

import pytest

from tests.helpers import load_json_fixture, serverless_profiles
from v2rm.engines.xray.generate import generate_config
from v2rm.engines.xray.raw import build_raw_runtime_config, udp_associate_address
from v2rm.models.auth import ProxyAuth
from v2rm.models.enums import Protocol
from v2rm.models.profile import Profile
from v2rm.routing.presets import BYPASS_IR, GLOBAL

LISTEN_ADDRESSES = ["127.0.0.1", "0.0.0.0", "172.18.0.1"]


def raw_profile(config: dict) -> Profile:
    return Profile(name="raw", protocol=Protocol.RAW_XRAY, raw_config=copy.deepcopy(config))


@pytest.mark.parametrize("listen", LISTEN_ADDRESSES)
def test_serverless_primary_inbound_uses_the_configured_listen_address_and_socks_port(listen):
    for profile in serverless_profiles():
        config = build_raw_runtime_config(profile, 10808, 10809, listen)
        primary = config["inbounds"][0]
        assert primary["tag"] == "mixed-in"
        assert primary["protocol"] == "mixed"
        assert primary["listen"] == listen  # explicit: the sample omits it, which Xray reads as 0.0.0.0
        assert primary["port"] == 10808


@pytest.mark.parametrize("listen", LISTEN_ADDRESSES)
def test_serverless_gets_an_http_inbound_on_the_http_port_with_the_same_sniffing(listen):
    profile = serverless_profiles()[0]
    config = build_raw_runtime_config(profile, 10808, 10809, listen)
    assert len(config["inbounds"]) == 2
    primary, twin = config["inbounds"]
    assert twin["tag"] == "mixed-in-http"
    assert twin["protocol"] == "http"
    assert twin["listen"] == listen
    assert twin["port"] == 10809
    assert twin["sniffing"] == primary["sniffing"]
    assert twin["sniffing"]["destOverride"] == ["fakedns", "tls", "http", "quic"]
    assert twin["sniffing"] is not primary["sniffing"]  # a copy, not the same object


def test_udp_associate_address_follows_a_specific_listen_address():
    profile = serverless_profiles()[0]
    # The sample pins settings.ip to 127.0.0.1 -- the address SOCKS5 UDP-associate
    # advertises. For a bridge IP that must follow the listen address, or clients
    # in containers would be told to send UDP to their own loopback.
    assert build_raw_runtime_config(profile, 1, 2, "172.18.0.1")["inbounds"][0]["settings"]["ip"] == "172.18.0.1"
    # Loopback / wildcard: nothing better to advertise, left as the config wrote it.
    assert build_raw_runtime_config(profile, 1, 2, "127.0.0.1")["inbounds"][0]["settings"]["ip"] == "127.0.0.1"
    assert build_raw_runtime_config(profile, 1, 2, "0.0.0.0")["inbounds"][0]["settings"]["ip"] == "127.0.0.1"


def test_udp_associate_address_helper():
    assert udp_associate_address("172.17.0.1") == "172.17.0.1"
    for default in ("127.0.0.1", "::1", "0.0.0.0", "::", ""):
        assert udp_associate_address(default) is None


@pytest.mark.parametrize("listen", LISTEN_ADDRESSES)
def test_everything_except_inbounds_is_left_exactly_as_written(listen):
    originals = load_json_fixture("serverless_subscription.json")
    for original, profile in zip(originals, serverless_profiles(), strict=True):
        config = build_raw_runtime_config(profile, 10808, 10809, listen)
        assert {k: v for k, v in config.items() if k != "inbounds"} == {
            k: v for k, v in original.items() if k != "inbounds"
        }
        # Unknown top-level keys and the version requirement survive.
        assert config["remarks"] == original["remarks"]
        assert config["__Credits__"] == original["__Credits__"]
        assert config["version"] == {"min": "26.6.27"}


def test_building_never_mutates_the_stored_config():
    profile = serverless_profiles()[0]
    before = copy.deepcopy(profile.raw_config)
    build_raw_runtime_config(profile, 10808, 10809, "172.18.0.1", ProxyAuth("u", "p"))
    assert profile.raw_config == before


def test_generate_config_dispatches_raw_profiles_and_ignores_routing_presets():
    profile = serverless_profiles()[0]
    a = generate_config(profile, GLOBAL, 10808, 10809, "127.0.0.1")
    b = generate_config(profile, BYPASS_IR, 10808, 10809, "127.0.0.1")
    assert a == b  # the preset doesn't apply: a raw profile brings its own routing
    assert a["routing"] == profile.raw_config["routing"]


def test_non_proxy_inbounds_are_dropped_with_a_note():
    notes: list[str] = []
    profile = raw_profile(
        {
            "inbounds": [
                {"tag": "tun-in", "protocol": "tun", "settings": {}},
                {"tag": "dokodemo", "protocol": "dokodemo-door", "port": 53},
                {"tag": "s", "protocol": "socks", "port": 1080, "settings": {"udp": True}},
            ],
            "outbounds": [],
        }
    )
    config = build_raw_runtime_config(profile, 10808, 10809, "127.0.0.1", notes=notes)
    assert [i["protocol"] for i in config["inbounds"]] == ["socks", "http"]
    assert len(notes) == 1
    assert "tun 'tun-in'" in notes[0] and "dokodemo-door 'dokodemo'" in notes[0]


def test_an_extra_proxy_inbound_is_dropped_too():
    notes: list[str] = []
    profile = raw_profile(
        {
            "inbounds": [
                {"tag": "a", "protocol": "socks", "port": 1},
                {"tag": "b", "protocol": "http", "port": 2},
            ],
            "outbounds": [],
        }
    )
    config = build_raw_runtime_config(profile, 10808, 10809, "127.0.0.1", notes=notes)
    assert [i["tag"] for i in config["inbounds"]] == ["a", "a-http"]
    assert "extra proxy inbound http 'b'" in notes[0]


def test_no_usable_inbounds_creates_socks_and_http_like_a_normal_profile():
    profile = raw_profile({"inbounds": [{"tag": "t", "protocol": "tun"}], "outbounds": []})
    config = build_raw_runtime_config(profile, 10808, 10809, "172.18.0.1")
    socks, http = config["inbounds"]
    assert (socks["protocol"], socks["port"], socks["listen"]) == ("socks", 10808, "172.18.0.1")
    assert (http["protocol"], http["port"], http["listen"]) == ("http", 10809, "172.18.0.1")
    assert socks["settings"]["ip"] == "172.18.0.1"


def test_a_config_with_no_inbounds_key_at_all_also_gets_the_defaults():
    config = build_raw_runtime_config(raw_profile({"outbounds": []}), 10808, 10809, "127.0.0.1")
    assert [i["protocol"] for i in config["inbounds"]] == ["socks", "http"]


def test_an_http_only_config_serves_http_on_the_http_port_and_gains_socks():
    profile = raw_profile({"inbounds": [{"tag": "h", "protocol": "http", "port": 3128}], "outbounds": []})
    config = build_raw_runtime_config(profile, 10808, 10809, "127.0.0.1")
    primary, twin = config["inbounds"]
    assert (primary["protocol"], primary["port"]) == ("http", 10809)
    assert (twin["protocol"], twin["port"], twin["tag"]) == ("socks", 10808, "h-socks")


def test_rules_matching_the_original_inbound_tag_also_match_the_http_twin():
    profile = raw_profile(
        {
            "inbounds": [{"tag": "in", "protocol": "mixed", "port": 1}],
            "outbounds": [],
            "routing": {
                "rules": [
                    {"inboundTag": ["in"], "outboundTag": "a"},
                    {"inboundTag": ["in", "other"], "outboundTag": "b"},
                    {"inboundTag": ["other"], "outboundTag": "c"},
                    {"outboundTag": "d", "port": "53"},
                ]
            },
        }
    )
    rules = build_raw_runtime_config(profile, 10808, 10809, "127.0.0.1")["routing"]["rules"]
    assert rules[0]["inboundTag"] == ["in", "in-http"]
    assert rules[1]["inboundTag"] == ["in", "other", "in-http"]
    assert rules[2]["inboundTag"] == ["other"]  # didn't mention the tag: untouched
    assert "inboundTag" not in rules[3]


def test_an_untagged_inbound_gets_a_tag():
    profile = raw_profile({"inbounds": [{"protocol": "socks", "port": 1}], "outbounds": []})
    primary, twin = build_raw_runtime_config(profile, 10808, 10809, "127.0.0.1")["inbounds"]
    assert primary["tag"] == "v2rm-in"
    assert twin["tag"] == "v2rm-in-http"


@pytest.mark.parametrize("listen", LISTEN_ADDRESSES)
def test_auth_accounts_appear_on_every_inbound(listen):
    auth = ProxyAuth("demo", "demo-pass")
    for profile in serverless_profiles():
        primary, twin = build_raw_runtime_config(profile, 10808, 10809, listen, auth)["inbounds"]
        assert primary["settings"]["auth"] == "password"  # without this Xray ignores the accounts
        assert primary["settings"]["accounts"] == [{"user": "demo", "pass": "demo-pass"}]
        assert twin["settings"]["accounts"] == [{"user": "demo", "pass": "demo-pass"}]


def test_no_auth_leaves_the_inbound_settings_alone():
    profile = serverless_profiles()[0]
    primary, twin = build_raw_runtime_config(profile, 10808, 10809, "127.0.0.1")["inbounds"]
    assert "accounts" not in primary["settings"]
    assert "accounts" not in twin["settings"]
