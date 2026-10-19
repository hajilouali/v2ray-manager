from __future__ import annotations

from tests.helpers import serverless_profiles
from v2rm.engines.xray.raw import is_serverless, profile_is_serverless
from v2rm.models.enums import Protocol
from v2rm.models.profile import Profile


def test_both_real_serverless_configs_are_recognised():
    profiles = serverless_profiles()
    assert len(profiles) == 2
    assert all(profile_is_serverless(p) for p in profiles)


def test_names_old_and_new_are_both_local_only():
    for names in (["freedom", "blackhole"], ["direct", "block", "dns"], ["freedom", "loopback"]):
        assert is_serverless({"outbounds": [{"protocol": n} for n in names]})


def test_any_outbound_to_a_remote_server_makes_it_a_normal_config():
    config = {"outbounds": [{"protocol": "vless", "settings": {}}, {"protocol": "direct"}, {"protocol": "block"}]}
    assert not is_serverless(config)
    for remote in ("vmess", "trojan", "shadowsocks", "socks", "http", "wireguard", "hysteria", "masque"):
        assert not is_serverless({"outbounds": [{"protocol": "direct"}, {"protocol": remote}]})


def test_a_config_it_cannot_judge_is_not_called_serverless():
    assert not is_serverless({})
    assert not is_serverless({"outbounds": []})
    assert not is_serverless({"outbounds": [{"tag": "no-protocol"}]})
    assert not is_serverless({"outbounds": ["junk", None]})


def test_only_raw_profiles_can_be_serverless():
    link_profile = Profile(name="t", protocol=Protocol.TROJAN, server="t.example.com", port=443, password="pw")
    assert not profile_is_serverless(link_profile)
    assert not profile_is_serverless(Profile(name="r", protocol=Protocol.RAW_XRAY))  # no config stored
