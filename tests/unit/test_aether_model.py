"""The Aether and chain parts of the Profile model."""

from __future__ import annotations

from v2rm.models.aether import AetherMode, AetherSettings
from v2rm.models.chain import HOP_PROFILE, HOP_PROXY, ChainHop
from v2rm.models.enums import Protocol
from v2rm.models.profile import Profile
from v2rm.store.profiles import ProfileStore


def aether_profile(**settings) -> Profile:
    return Profile(name="warp", protocol=Protocol.AETHER, aether=AetherSettings(**settings))


def test_settings_round_trip_through_a_dict():
    settings = AetherSettings(
        mode=AetherMode.GOOL_CLASSIC,
        transport="",
        outer="162.159.192.1:2408",
        inner="188.114.96.1:2408",
        noize="gfw",
        fragment=True,
        fragment_size="8-16",
        route_block=["ads.example"],
        route_direct=["private", "port:25"],
        quick_reconnect=False,
        reconnect_secs=3,
        dns=["1.1.1.1"],
        upstream="socks5://127.0.0.1:1080",
        wait_secs=300,
        env={"AETHER_TEAM": "acme"},
    )
    assert AetherSettings.from_dict(settings.to_dict()) == settings


def test_defaults_leave_everything_to_aether():
    settings = AetherSettings()
    assert settings.mode == AetherMode.MASQUE
    assert settings.transport == "" and settings.scan == "" and settings.noize == ""
    assert settings.quick_reconnect is True and settings.route_sniff is True and settings.quic_v2 is True
    assert settings.reconnect_secs is None and settings.fragment is False


def test_from_dict_ignores_unknown_keys_and_fills_missing_ones():
    settings = AetherSettings.from_dict({"mode": "wg", "from_the_future": 1})
    assert settings.mode == AetherMode.WG
    assert settings.route_block == [] and settings.quick_reconnect is True


def test_from_dict_survives_junk():
    settings = AetherSettings.from_dict({"mode": "nonsense", "reconnect_secs": "x", "dns": None, "env": [1]})
    assert settings.mode == AetherMode.MASQUE
    assert settings.reconnect_secs is None and settings.dns == [] and settings.env == {}
    assert AetherSettings.from_dict(None) == AetherSettings()


def test_a_single_string_where_a_list_is_expected_becomes_a_one_item_list():
    assert AetherSettings.from_dict({"route_block": "ads.example"}).route_block == ["ads.example"]


def test_summary_reads_like_a_server_column():
    assert AetherSettings().summary() == "WARP masque"
    assert AetherSettings(transport="h2", fragment=True, noize="gfw").summary() == "WARP masque/h2 +fragment +noize:gfw"
    assert AetherSettings(mode=AetherMode.GOOL_CLASSIC).summary() == "WARP gool-classic"
    # WireGuard has no carrier choice to show.
    assert AetherSettings(mode=AetherMode.WG, transport="h3").summary() == "WARP wg"


# ---- inside a Profile ---------------------------------------------------------------------------


def test_an_aether_profile_round_trips_and_has_no_server():
    profile = aether_profile(mode=AetherMode.MIM, transport="h2")
    again = Profile.from_dict(profile.to_dict())
    assert again.aether == profile.aether
    assert again.protocol == Protocol.AETHER and again.is_aether and not again.is_chain
    assert again.type_label == "aether"
    assert again.server_display == "WARP mim/h2"
    assert again.chain is None and again.raw_config is None


def test_a_chain_profile_round_trips_and_shows_its_hops_in_order():
    hops = [
        ChainHop(HOP_PROFILE, "abc123", "my vless"),
        ChainHop(HOP_PROXY, "socks5://u:p@127.0.0.1:1080"),
        ChainHop(HOP_PROFILE, "def456", "warp"),
    ]
    profile = Profile(name="chain", protocol=Protocol.CHAIN, chain=hops)
    again = Profile.from_dict(profile.to_dict())
    assert again.chain == hops
    assert again.is_chain and again.type_label == "chain"
    assert again.server_display == "my vless -> socks5://u:***@127.0.0.1:1080 -> warp"


def test_an_ordinary_profile_is_unaffected():
    plain = Profile(name="t", protocol=Protocol.TROJAN, server="t.example.com", port=443, password="pw")
    data = plain.to_dict()
    assert data["aether"] is None and data["chain"] is None
    assert Profile.from_dict(data).server_display == "t.example.com:443"


def test_a_profile_stored_by_an_older_v2rm_has_neither_field():
    data = Profile(name="t", protocol=Protocol.TROJAN, server="t.example.com", port=443).to_dict()
    del data["aether"], data["chain"]
    loaded = Profile.from_dict(data)
    assert loaded.aether is None and loaded.chain is None


def test_identity_is_the_profiles_own_id():
    one, two = aether_profile(), aether_profile()
    assert one.identity_key() == ("aether", one.id)
    assert one.identity_key() != two.identity_key()
    chain = Profile(name="c", protocol=Protocol.CHAIN, chain=[])
    assert chain.identity_key() == ("chain", chain.id)


def test_the_store_keeps_both_kinds():
    store = ProfileStore()
    warp = store.add(aether_profile(transport="h2", route_block=["ads.example"]))
    chain = store.add(
        Profile(name="c", protocol=Protocol.CHAIN, chain=[ChainHop(HOP_PROFILE, warp.id, warp.name)])
    )
    loaded = {p.id: p for p in store.list()}
    assert loaded[warp.id].aether.transport == "h2"
    assert loaded[warp.id].aether.route_block == ["ads.example"]
    assert loaded[chain.id].chain[0].ref == warp.id


def test_hop_labels_never_reveal_a_proxy_password():
    assert ChainHop(HOP_PROXY, "socks5://u:hunter2@h:1080").label() == "socks5://u:***@h:1080"
    assert ChainHop(HOP_PROFILE, "id", "Name").label() == "Name"
    assert ChainHop(HOP_PROFILE, "id", "").label() == "id"
    assert ChainHop.from_dict({"kind": "weird", "ref": "x"}).kind == HOP_PROFILE
