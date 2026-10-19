from __future__ import annotations

from v2rm.models.enums import Protocol, SecurityKind, TransportKind
from v2rm.models.profile import (
    NO_SERVER,
    SCHEMA_VERSION,
    Profile,
    TlsSettings,
    TransportSettings,
)
from v2rm.models.subscription import Subscription
from v2rm.store.profiles import ProfileStore


def make_vless(**overrides) -> Profile:
    base = dict(
        name="node",
        protocol=Protocol.VLESS,
        server="188.114.98.0",
        port=443,
        uuid="5504eaa8-1395-402f-8e0e-75ecd762e627",
        transport=TransportSettings(network=TransportKind.WS, path="/p", host="h.example.com"),
        tls=TlsSettings(security=SecurityKind.TLS, sni="h.example.com", fingerprint="chrome"),
    )
    base.update(overrides)
    return Profile(**base)


def test_new_fields_round_trip_through_dict():
    p = make_vless(
        encryption="mlkem768x25519plus.native.0rtt.KEY",
        packet_encoding="xudp",
        tls=TlsSettings(
            security=SecurityKind.TLS,
            sni="h.example.com",
            fingerprint="unsafe",
            cipher_suites="TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256",
            ech_config_list="cloudflare-ech.com+udp://1.1.1.1",
        ),
        transport=TransportSettings(
            network=TransportKind.XHTTP,
            path="/x",
            host="h.example.com",
            mode="auto",
            xhttp_extra={"xPaddingBytes": "100-1000"},
            finalmask={"tcp": [{"type": "fragment", "settings": {"packets": "tlshello"}}]},
            headers={"X-Test": "1"},
        ),
    )
    q = Profile.from_dict(p.to_dict())
    assert q.encryption == p.encryption
    assert q.packet_encoding == "xudp"
    assert q.tls.cipher_suites == p.tls.cipher_suites
    assert q.tls.ech_config_list == p.tls.ech_config_list
    assert q.tls.fingerprint == "unsafe"
    assert q.transport.mode == "auto"
    assert q.transport.xhttp_extra == {"xPaddingBytes": "100-1000"}
    assert q.transport.finalmask == p.transport.finalmask
    assert q.transport.headers == {"X-Test": "1"}
    assert q.schema == SCHEMA_VERSION


def test_profile_stored_by_an_older_version_still_loads():
    # What an already-deployed install has on disk: none of the new keys, no
    # "schema", and a server/port. Must load without error, defaulting new
    # fields and flagging schema 1 so the store can upgrade it from raw_link.
    old = {
        "id": "abc123abc123",
        "name": "old",
        "protocol": "vless",
        "server": "1.2.3.4",
        "port": 443,
        "uuid": "u",
        "transport": {"network": "ws", "path": "/p", "host": "h"},
        "tls": {"security": "tls", "sni": "h", "alpn": [], "fingerprint": "chrome", "allow_insecure": False},
        "extra": {},
    }
    p = Profile.from_dict(old)
    assert p.schema == 1
    assert p.encryption == ""
    assert p.tls.cipher_suites == ""
    assert p.transport.finalmask == {}
    assert p.raw_config is None


def test_raw_profile_has_no_server_and_keeps_its_config():
    cfg = {"remarks": "Serverless-v52-fragA", "outbounds": [{"protocol": "direct", "tag": "d"}]}
    p = Profile(name="Serverless-v52-fragA", protocol=Protocol.RAW_XRAY, raw_config=cfg)
    assert p.server == "" and p.port == 0
    assert p.is_raw
    assert p.type_label == "raw"
    assert p.server_display == NO_SERVER

    q = Profile.from_dict(p.to_dict())
    assert q.raw_config == cfg
    # deep-copied: mutating the copy can't corrupt the original
    q.raw_config["outbounds"].append({"protocol": "block"})
    assert len(p.raw_config["outbounds"]) == 1


def test_type_label_and_server_display_for_normal_profiles():
    p = make_vless()
    assert p.type_label == "vless"
    assert p.server_display == "188.114.98.0:443"


def test_identity_key_ignores_name():
    assert make_vless(name="a").identity_key() == make_vless(name="b").identity_key()


def test_identity_key_distinguishes_variants_of_the_same_node():
    # Free-Configs ships each healthy node several times, differing only in
    # fp / cs / fm / ech. The old key (protocol+server+port+uuid) collapsed them.
    a = make_vless()
    b = make_vless(
        tls=TlsSettings(
            security=SecurityKind.TLS,
            sni="h.example.com",
            fingerprint="unsafe",
            cipher_suites="TLS_AES_256_GCM_SHA384",
        ),
    )
    c = make_vless(
        tls=TlsSettings(
            security=SecurityKind.TLS,
            sni="h.example.com",
            fingerprint="chrome",
            ech_config_list="cloudflare-ech.com+udp://1.1.1.1",
        ),
    )
    d = make_vless(
        transport=TransportSettings(
            network=TransportKind.WS, path="/p", host="h.example.com", finalmask={"tcp": [{"type": "fragment"}]}
        )
    )
    keys = {a.identity_key(), b.identity_key(), c.identity_key(), d.identity_key()}
    assert len(keys) == 4


def test_identity_key_distinguishes_sni_host_path_network():
    base = make_vless()
    assert base.identity_key() != make_vless(
        tls=TlsSettings(security=SecurityKind.TLS, sni="other.example.com", fingerprint="chrome")
    ).identity_key()
    assert base.identity_key() != make_vless(
        transport=TransportSettings(network=TransportKind.WS, path="/other", host="h.example.com")
    ).identity_key()
    assert base.identity_key() != make_vless(
        transport=TransportSettings(network=TransportKind.XHTTP, path="/p", host="h.example.com")
    ).identity_key()
    assert base.identity_key() != make_vless(
        transport=TransportSettings(network=TransportKind.WS, path="/p", host="other-host.example.com")
    ).identity_key()


def test_identity_key_for_encryption_and_xhttp_extra_and_mode():
    base = make_vless()
    assert base.identity_key() != make_vless(encryption="mlkem768x25519plus.native.0rtt.K").identity_key()
    extra = make_vless(
        transport=TransportSettings(
            network=TransportKind.WS, path="/p", host="h.example.com", xhttp_extra={"a": 1}
        )
    )
    mode = make_vless(
        transport=TransportSettings(network=TransportKind.WS, path="/p", host="h.example.com", mode="auto")
    )
    assert len({base.identity_key(), extra.identity_key(), mode.identity_key()}) == 3


def test_identity_key_is_stable_regardless_of_dict_ordering():
    a = make_vless(
        transport=TransportSettings(
            network=TransportKind.WS, path="/p", host="h.example.com", finalmask={"a": 1, "b": 2}
        )
    )
    b = make_vless(
        transport=TransportSettings(
            network=TransportKind.WS, path="/p", host="h.example.com", finalmask={"b": 2, "a": 1}
        )
    )
    assert a.identity_key() == b.identity_key()


def test_identity_key_keeps_the_old_shape_for_other_protocols():
    p = Profile(name="h", protocol=Protocol.HYSTERIA2, server="h.example.com", port=443, password="pw")
    assert p.identity_key() == ("hysteria2", "h.example.com", "443", "", "pw")


def test_raw_identity_key_uses_remarks_when_present():
    a = Profile(name="x", protocol=Protocol.RAW_XRAY, raw_config={"remarks": "R", "outbounds": [{"tag": "a"}]})
    b = Profile(name="y", protocol=Protocol.RAW_XRAY, raw_config={"remarks": "R", "outbounds": [{"tag": "b"}]})
    assert a.identity_key() == b.identity_key() == ("raw-xray", "R")


def test_raw_identity_key_falls_back_to_content_hash_without_remarks():
    a = Profile(name="x", protocol=Protocol.RAW_XRAY, raw_config={"outbounds": [{"tag": "a"}]})
    a2 = Profile(name="x", protocol=Protocol.RAW_XRAY, raw_config={"outbounds": [{"tag": "a"}]})
    b = Profile(name="x", protocol=Protocol.RAW_XRAY, raw_config={"outbounds": [{"tag": "b"}]})
    assert a.identity_key() == a2.identity_key()
    assert a.identity_key() != b.identity_key()
    assert a.identity_key()[1].startswith("sha256:")


def test_raw_identity_key_hash_is_independent_of_key_order():
    a = Profile(name="x", protocol=Protocol.RAW_XRAY, raw_config={"outbounds": [], "log": {"x": 1, "y": 2}})
    b = Profile(name="x", protocol=Protocol.RAW_XRAY, raw_config={"log": {"y": 2, "x": 1}, "outbounds": []})
    assert a.identity_key() == b.identity_key()


def test_masque_identity_key():
    a = Profile(
        name="m", protocol=Protocol.MASQUE, server="m.example.com", port=443,
        tls=TlsSettings(security=SecurityKind.TLS, sni="m.example.com"),
        transport=TransportSettings(path="/masque"), extra={"user": "u"},
    )
    b = Profile(
        name="other name", protocol=Protocol.MASQUE, server="m.example.com", port=443,
        tls=TlsSettings(security=SecurityKind.TLS, sni="m.example.com"),
        transport=TransportSettings(path="/masque"), extra={"user": "u"},
    )
    c = Profile(
        name="m", protocol=Protocol.MASQUE, server="m.example.com", port=443,
        tls=TlsSettings(security=SecurityKind.TLS, sni="m.example.com"),
        transport=TransportSettings(path="/masque"), extra={"user": "different"},
    )
    assert a.identity_key() == b.identity_key()
    assert a.identity_key() != c.identity_key()


def test_subscription_update_interval_round_trips_and_defaults_to_none():
    sub = Subscription(name="s", url="https://example.com/x", update_interval_hours=1.0)
    assert Subscription.from_dict(sub.to_dict()).update_interval_hours == 1.0
    old = {"id": "i", "name": "n", "url": "u"}
    assert Subscription.from_dict(old).update_interval_hours is None


def test_store_update_many_replaces_in_one_pass():
    store = ProfileStore()
    p1 = make_vless(name="one", server="1.example.com")
    p2 = make_vless(name="two", server="2.example.com")
    p3 = make_vless(name="three", server="3.example.com")
    store.add_many([p1, p2, p3])

    p1.name = "ONE"
    p3.name = "THREE"
    ghost = make_vless(name="ghost")  # not stored -> skipped
    assert store.update_many([p1, p3, ghost]) == 2

    names = {p.id: p.name for p in store.list()}
    assert names[p1.id] == "ONE"
    assert names[p2.id] == "two"
    assert names[p3.id] == "THREE"
    assert len(names) == 3


def test_store_update_many_with_nothing_is_a_noop():
    assert ProfileStore().update_many([]) == 0
