from __future__ import annotations

import pytest

from v2rm.errors import AmbiguousReferenceError, ProfileNotFoundError
from v2rm.models.enums import Protocol
from v2rm.models.profile import Profile
from v2rm.models.subscription import Subscription
from v2rm.store.profiles import ProfileStore
from v2rm.store.state import AppStateStore
from v2rm.store.subscriptions import SubscriptionStore


def make_profile(name: str = "test", server: str = "example.com", port: int = 443) -> Profile:
    return Profile(name=name, protocol=Protocol.VLESS, server=server, port=port, uuid="abc-123")


def test_profile_round_trip():
    store = ProfileStore()
    p = make_profile()
    store.add(p)

    loaded = store.get(p.id)
    assert loaded is not None
    assert loaded.name == "test"
    assert loaded.server == "example.com"
    assert loaded.protocol == Protocol.VLESS
    assert loaded.uuid == "abc-123"


def test_profile_resolve_by_id_prefix_and_name():
    store = ProfileStore()
    p = make_profile(name="myprofile")
    store.add(p)

    assert store.resolve(p.id).id == p.id
    assert store.resolve(p.id[:6]).id == p.id
    assert store.resolve("myprofile").id == p.id

    with pytest.raises(ProfileNotFoundError):
        store.resolve("does-not-exist")


def test_profile_resolve_ambiguous_name():
    store = ProfileStore()
    store.add(make_profile(name="dup", server="a.com"))
    store.add(make_profile(name="dup", server="b.com"))

    with pytest.raises(AmbiguousReferenceError):
        store.resolve("dup")


def test_profile_update_and_remove():
    store = ProfileStore()
    p = make_profile()
    store.add(p)

    p.name = "renamed"
    store.update(p)
    assert store.get(p.id).name == "renamed"

    store.remove(p.id)
    assert store.get(p.id) is None
    with pytest.raises(ProfileNotFoundError):
        store.remove(p.id)


def test_profile_add_many_and_list_by_subscription():
    store = ProfileStore()
    p1 = make_profile(name="a", server="a.com")
    p1.subscription_id = "sub1"
    p2 = make_profile(name="b", server="b.com")
    p2.subscription_id = "sub1"
    p3 = make_profile(name="c", server="c.com")

    store.add_many([p1, p2, p3])

    members = store.list_by_subscription("sub1")
    assert {p.name for p in members} == {"a", "b"}
    assert len(store.list()) == 3


def test_subscription_round_trip():
    store = SubscriptionStore()
    sub = Subscription(name="myprovider", url="https://example.com/sub")
    store.add(sub)

    loaded = store.resolve("myprovider")
    assert loaded.url == "https://example.com/sub"
    assert loaded.last_status == "never"


def test_app_state_defaults_and_persistence():
    store = AppStateStore()
    state = store.load()
    assert state.active_profile_id is None
    assert state.socks_port == 10808
    assert state.http_port == 10809

    state.active_profile_id = "abc"
    store.save(state)

    reloaded = store.load()
    assert reloaded.active_profile_id == "abc"


def test_app_state_listen_address_round_trip():
    store = AppStateStore()
    state = store.load()
    assert state.listen_address == "127.0.0.1"

    state.listen_address = "172.17.0.1"
    store.save(state)

    assert store.load().listen_address == "172.17.0.1"


def test_app_state_from_dict_defaults_listen_address_when_absent():
    # A state.json written before this field existed (e.g. an already-
    # deployed install) has no "listen_address" key at all -- it must load
    # cleanly rather than raise, defaulting to the safe loopback-only value.
    from v2rm.models.state import AppState

    state = AppState.from_dict({"active_profile_id": "abc", "socks_port": 10808, "http_port": 10809})
    assert state.listen_address == "127.0.0.1"
