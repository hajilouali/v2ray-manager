"""What v2rm decides to run for an Aether profile or a chain. Nothing is started here."""

from __future__ import annotations

import itertools

import pytest

from tests.helpers import serverless_profiles
from v2rm.engines.xray.generate import UPSTREAM_TAG
from v2rm.errors import ProfileNotFoundError, ProfileValidationError
from v2rm.models.aether import AetherMode, AetherSettings
from v2rm.models.auth import ProxyAuth
from v2rm.models.chain import HOP_PROFILE, HOP_PROXY, ChainHop
from v2rm.models.enums import EngineKind, Protocol
from v2rm.models.profile import Profile
from v2rm.process import stack
from v2rm.routing.presets import BYPASS_IR, GLOBAL
from v2rm.store import paths
from v2rm.store.profiles import ProfileStore

XRAY, SINGBOX, AETHER = EngineKind.XRAY, EngineKind.SINGBOX, EngineKind.AETHER


def counter(start=41000):
    numbers = itertools.count(start)
    return lambda avoid=None: next(numbers)


def add_aether(name="warp", **settings) -> Profile:
    return ProfileStore().add(Profile(name=name, protocol=Protocol.AETHER, aether=AetherSettings(**settings)))


def add_trojan(name="trojan") -> Profile:
    return ProfileStore().add(
        Profile(name=name, protocol=Protocol.TROJAN, server=f"{name}.example.com", port=443, password="pw")
    )


def add_hysteria2(name="hy2") -> Profile:
    return ProfileStore().add(
        Profile(name=name, protocol=Protocol.HYSTERIA2, server=f"{name}.example.com", port=443, password="pw")
    )


def hop(item) -> ChainHop:
    if isinstance(item, str):
        return ChainHop(HOP_PROXY, item)
    return ChainHop(HOP_PROFILE, item.id, item.name)


def add_chain(name, *items) -> Profile:
    return ProfileStore().add(Profile(name=name, protocol=Protocol.CHAIN, chain=[hop(i) for i in items]))


def plan(profile, route=GLOBAL, auth=None, listen="127.0.0.1", preferred=None, ports=None):
    return stack.plan_stack(
        profile,
        ProfileStore(),
        preferred_engine=preferred,
        route_plan=route,
        socks_port=10808,
        http_port=10809,
        listen_address=listen,
        auth=auth,
        ports=ports or counter(),
    )


def labels(p):
    return [s.label for s in p.stages]


# ---- an Aether profile on its own -----------------------------------------------------------------


def test_a_lone_aether_profile_listens_where_the_user_asked_with_nothing_in_front():
    warp = add_aether()
    p = plan(warp)

    (stage,) = p.stages
    assert stage.engine == AETHER and stage.user_facing and stage.ready == stack.READY_SOCKS5
    assert stage.env["AETHER_SOCKS"] == "127.0.0.1:10808"
    assert stage.env["AETHER_HTTP_PROXY"] == "127.0.0.1:10809"
    assert stage.socks_port == 10808 and stage.http_port == 10809
    assert stage.workdir == paths.aether_profile_dir(warp.id)
    assert stage.env["AETHER_CONFIG"] == str(paths.aether_profile_dir(warp.id) / "aether.toml")
    assert p.hops == [warp.name] and p.aether_ids == [warp.id]
    assert p.user_facing is stage


def test_aether_may_bind_a_docker_address_or_a_wildcard_by_itself_without_a_login():
    warp = add_aether()
    assert plan(warp, listen="172.17.0.1").stages[0].env["AETHER_SOCKS"] == "172.17.0.1:10808"
    assert plan(warp, listen="0.0.0.0").stages[0].env["AETHER_SOCKS"] == "0.0.0.0:10808"
    assert plan(warp, listen="::1").stages[0].env["AETHER_SOCKS"] == "[::1]:10808"


def test_a_login_puts_an_xray_front_in_front_of_aether():
    warp = add_aether()
    p = plan(warp, auth=ProxyAuth("user", "pw"), listen="172.17.0.1", ports=counter(41000))

    aether, front = p.stages
    assert aether.engine == AETHER and not aether.user_facing
    assert aether.env["AETHER_SOCKS"] == "127.0.0.1:41000" and "AETHER_HTTP_PROXY" not in aether.env
    assert front.engine == XRAY and front.user_facing and front.profile is None
    assert (front.socks_port, front.http_port, front.listen) == (10808, 10809, "172.17.0.1")
    socks_in, http_in = front.config["inbounds"]
    assert socks_in["listen"] == "172.17.0.1" and socks_in["settings"]["accounts"] == [{"user": "user", "pass": "pw"}]
    assert http_in["settings"]["accounts"] == [{"user": "user", "pass": "pw"}]
    (server,) = front.config["outbounds"][0]["settings"]["servers"]
    assert server == {"address": "127.0.0.1", "port": 41000}
    assert any("front" in n for n in p.notes)
    assert p.user_facing is front


def test_a_route_preset_also_needs_the_front():
    p = plan(add_aether(), route=BYPASS_IR)
    assert [s.engine for s in p.stages] == [AETHER, XRAY]
    assert any(r.get("outboundTag") == "direct" for r in p.stages[1].config["routing"]["rules"])


def test_the_front_is_checked_by_xray_first_only_when_a_preset_needs_geo_data():
    assert plan(add_aether(), route=BYPASS_IR).stages[1].preflight is True
    assert plan(add_aether(), auth=ProxyAuth("u", "p")).stages[1].preflight is False


def test_how_long_to_wait_for_aether_is_the_profiles_choice_or_the_default():
    assert plan(add_aether()).stages[0].ready_timeout == 120.0
    assert plan(add_aether(wait_secs=300)).stages[0].ready_timeout == 300.0


def test_the_global_preset_without_a_login_needs_no_xray_at_all():
    assert [s.engine for s in plan(add_aether()).stages] == [AETHER]


def test_an_aether_profiles_own_upstream_is_used_when_it_stands_alone():
    warp = add_aether(upstream="socks5://127.0.0.1:1080")
    env = plan(warp).stages[0].env
    assert env["AETHER_UPSTREAM"] == "socks5://127.0.0.1:1080"
    assert env["AETHER_MASQUE_HTTP2"] == "0"  # a socks upstream carries UDP, so HTTP/3 stays


def test_the_first_connection_says_it_will_register_a_device():
    warp = add_aether()
    assert any("registers a free anonymous Cloudflare WARP device" in n for n in plan(warp).notes)
    identity = paths.aether_profile_dir(warp.id) / "aether-masque.toml"
    identity.parent.mkdir(parents=True)
    identity.write_text("keys")
    assert not any("registers" in n for n in plan(warp).notes)


def test_a_mode_that_needs_two_identities_registers_until_it_has_both():
    warp = add_aether(mode=AetherMode.GOOL_CLASSIC)
    directory = paths.aether_profile_dir(warp.id)
    directory.mkdir(parents=True)
    (directory / "aether.toml").write_text("keys")
    assert any("registers" in n for n in plan(warp).notes)


# ---- chains ------------------------------------------------------------------------------------


def test_aether_then_a_server_the_server_is_dialled_through_the_warp_tunnel():
    warp, server = add_aether(), add_trojan()
    p = plan(add_chain("via warp", warp, server), ports=counter(41000))

    first, last = p.stages
    assert first.engine == AETHER and not first.user_facing and first.socks_port == 41000
    assert first.env["AETHER_SOCKS"] == "127.0.0.1:41000" and "AETHER_UPSTREAM" not in first.env
    assert last.engine == XRAY and last.user_facing and last.profile.id == server.id
    proxy = next(o for o in last.config["outbounds"] if o["tag"] == "proxy")
    assert proxy["streamSettings"]["sockopt"]["dialerProxy"] == UPSTREAM_TAG
    hop = next(o for o in last.config["outbounds"] if o["tag"] == UPSTREAM_TAG)
    assert hop["settings"]["servers"] == [{"address": "127.0.0.1", "port": 41000}]
    assert last.preflight  # a chained config is checked by the engine first
    assert p.hops == [warp.name, server.name]


def test_the_last_hop_carries_the_users_listeners_login_and_route_preset():
    warp, server = add_aether(), add_trojan()
    p = plan(add_chain("c", warp, server), route=BYPASS_IR, auth=ProxyAuth("u", "p"), listen="0.0.0.0")
    last = p.stages[-1]
    assert (last.socks_port, last.http_port, last.listen) == (10808, 10809, "0.0.0.0")
    assert last.config["inbounds"][0]["settings"]["accounts"] == [{"user": "u", "pass": "p"}]
    assert any(r.get("outboundTag") == "direct" for r in last.config["routing"]["rules"])
    assert len(p.stages) == 2  # no front: the last hop is an Xray that does all of it itself


def test_the_earlier_hops_listen_on_loopback_without_login_or_preset():
    warp, server, other = add_aether(), add_trojan("one"), add_trojan("two")
    p = plan(add_chain("c", server, warp, other), route=BYPASS_IR, auth=ProxyAuth("u", "p"), listen="0.0.0.0")
    first = p.stages[0]
    assert first.listen == "127.0.0.1" and not first.user_facing
    assert first.config["inbounds"][0]["listen"] == "127.0.0.1"
    assert "accounts" not in first.config["inbounds"][0]["settings"]
    assert first.config["routing"]["rules"] == [{"type": "field", "outboundTag": "proxy", "port": "0-65535"}]


def test_a_server_then_aether_aether_dials_the_warp_edge_through_the_server():
    server, warp = add_trojan(), add_aether()
    p = plan(add_chain("warp exit", server, warp), ports=counter(41000))

    first, last = p.stages
    assert first.engine == XRAY and first.socks_port == 41000 and not first.user_facing
    assert last.engine == AETHER and last.user_facing
    assert last.env["AETHER_UPSTREAM"] == "socks5://127.0.0.1:41000"
    assert last.env["AETHER_SOCKS"] == "127.0.0.1:10808"
    assert last.env["AETHER_MASQUE_HTTP2"] == "1"  # TCP through the previous hop unless told otherwise
    assert any("previous hop" in n for n in p.notes)


def test_a_server_then_aether_with_a_login_adds_the_front():
    server, warp = add_trojan(), add_aether()
    p = plan(add_chain("c", server, warp), auth=ProxyAuth("u", "p"))
    assert [s.engine for s in p.stages] == [XRAY, AETHER, XRAY]
    assert [s.user_facing for s in p.stages] == [False, False, True]
    assert p.hops == [server.name, warp.name]  # the front is not a hop the user chained


def test_an_explicit_http3_choice_is_kept_through_a_chain():
    server, warp = add_trojan(), add_aether(transport="h3")
    assert plan(add_chain("c", server, warp)).stages[-1].env["AETHER_MASQUE_HTTP2"] == "0"


def test_a_proxy_already_running_can_be_the_first_hop_of_an_aether_profile():
    warp = add_aether()
    p = plan(add_chain("c", "socks5://user:pw@127.0.0.1:1080", warp))
    (stage,) = p.stages
    assert stage.env["AETHER_UPSTREAM"] == "socks5://user:pw@127.0.0.1:1080"
    assert p.hops == ["socks5://user:***@127.0.0.1:1080", warp.name]


def test_a_proxy_already_running_can_be_the_first_hop_of_a_server():
    server = add_trojan()
    p = plan(add_chain("c", "http://proxy.example:8080", server))
    (stage,) = p.stages
    hop = next(o for o in stage.config["outbounds"] if o["tag"] == UPSTREAM_TAG)
    assert hop["protocol"] == "http"
    assert hop["settings"]["servers"] == [{"address": "proxy.example", "port": 8080}]


def test_a_singbox_only_protocol_is_a_hop_like_any_other():
    warp, hy2 = add_aether(), add_hysteria2()
    p = plan(add_chain("c", warp, hy2), ports=counter(41000))
    last = p.stages[-1]
    assert last.engine == SINGBOX
    proxy = next(o for o in last.config["outbounds"] if o["tag"] == "proxy")
    assert proxy["detour"] == "v2rm-upstream"


def test_three_hops():
    one, warp, two = add_trojan("one"), add_aether(), add_trojan("two")
    p = plan(add_chain("c", one, warp, two), ports=counter(41000))
    assert [s.engine for s in p.stages] == [XRAY, AETHER, XRAY]
    assert p.stages[1].env["AETHER_UPSTREAM"] == f"socks5://127.0.0.1:{p.stages[0].socks_port}"
    dialer = next(o for o in p.stages[2].config["outbounds"] if o["tag"] == UPSTREAM_TAG)
    assert dialer["settings"]["servers"][0]["port"] == p.stages[1].socks_port


def test_internal_ports_are_all_different_and_the_users_are_untouched():
    one, warp, two = add_trojan("one"), add_aether(), add_trojan("two")
    p = plan(add_chain("c", one, warp, two))
    internal = [s.socks_port for s in p.stages[:-1]] + [s.http_port for s in p.stages[:-1] if s.http_port]
    assert len(internal) == len(set(internal))
    assert 10808 not in internal and 10809 not in internal
    assert (p.stages[-1].socks_port, p.stages[-1].http_port) == (10808, 10809)


def test_a_chain_of_chains_is_unfolded_in_order():
    a, b, c = add_trojan("a"), add_aether("b"), add_trojan("c")
    inner = add_chain("inner", a, b)
    outer = add_chain("outer", inner, c)
    assert plan(outer).hops == ["a", "b", "c"]


def test_a_raw_config_can_open_a_chain():
    raw = serverless_profiles()[0]
    raw.id = ""
    raw = ProfileStore().add(raw)
    warp = add_aether()
    p = plan(add_chain("c", raw, warp))
    assert p.stages[0].profile.is_raw and p.stages[1].engine == AETHER


def test_the_engine_a_user_prefers_is_used_where_either_would_do():
    server = add_trojan()
    assert plan(add_chain("c", add_aether(), server), preferred=SINGBOX).stages[-1].engine == SINGBOX


# ---- what a chain may not be ---------------------------------------------------------------------


def test_an_empty_chain_or_a_lone_proxy_is_not_a_chain():
    with pytest.raises(ProfileValidationError, match="no connection"):
        plan(add_chain("empty"))
    with pytest.raises(ProfileValidationError, match="no connection"):
        plan(add_chain("proxy only", "socks5://127.0.0.1:1080"))


def test_a_proxy_address_must_come_first():
    with pytest.raises(ProfileValidationError, match="only be the first hop"):
        plan(add_chain("c", add_trojan(), "socks5://127.0.0.1:1080", add_aether()))


def test_a_raw_config_must_come_first():
    raw = serverless_profiles()[0]
    raw.id = ""
    raw = ProfileStore().add(raw)
    with pytest.raises(ProfileValidationError, match="can only be the first hop"):
        plan(add_chain("c", add_aether(), raw))


def test_the_same_aether_profile_cannot_appear_twice():
    warp = add_aether()
    with pytest.raises(ProfileValidationError, match="appears twice"):
        plan(add_chain("c", warp, add_trojan(), warp))


def test_an_aether_profile_with_its_own_upstream_cannot_follow_another_hop():
    warp = add_aether(upstream="socks5://127.0.0.1:1080")
    with pytest.raises(ProfileValidationError, match="already has an upstream"):
        plan(add_chain("c", add_trojan(), warp))
    plan(add_chain("fine", warp, add_trojan()))  # first, it is the entry: its upstream is the first hop


def test_too_many_hops():
    hops = [add_trojan(f"t{i}") for i in range(stack.MAX_PROFILE_HOPS + 1)]
    with pytest.raises(ProfileValidationError, match="at most"):
        plan(add_chain("c", *hops))


def test_a_chain_cannot_contain_itself():
    store = ProfileStore()
    loop = store.add(Profile(name="loop", protocol=Protocol.CHAIN, chain=[]))
    loop.chain = [ChainHop(HOP_PROFILE, loop.id, "loop"), hop(add_trojan())]
    store.update(loop)
    with pytest.raises(ProfileValidationError, match="contains itself"):
        plan(loop)


def test_a_deleted_member_is_reported_by_name():
    gone, warp = add_trojan("gone"), add_aether()
    chain = add_chain("c", warp, gone)
    ProfileStore().remove(gone.id)
    with pytest.raises(ProfileNotFoundError, match="no longer exists") as caught:
        plan(chain)
    assert "gone" in str(caught.value) and "c" in str(caught.value)


def test_a_member_recreated_under_a_new_id_is_found_by_name():
    old, warp = add_trojan("node"), add_aether()
    chain = add_chain("c", warp, old)
    ProfileStore().remove(old.id)
    new = add_trojan("node")
    p = plan(chain)
    assert p.stages[-1].profile.id == new.id


def test_two_members_with_that_name_are_ambiguous_not_guessed():
    old, warp = add_trojan("node"), add_aether()
    chain = add_chain("c", warp, old)
    ProfileStore().remove(old.id)
    add_trojan("node")
    ProfileStore().add(Profile(name="node", protocol=Protocol.TROJAN, server="x.example.com", port=443, password="pw"))
    with pytest.raises(ProfileNotFoundError, match="several"):
        plan(chain)


def test_an_aether_profile_with_invalid_settings_is_refused_before_anything_starts():
    bad = ProfileStore().add(
        Profile(name="bad", protocol=Protocol.AETHER, aether=AetherSettings(mode=AetherMode.WG, transport="h2"))
    )
    with pytest.raises(ProfileValidationError, match="UDP all the way"):
        plan(bad)


# ---- bookkeeping ---------------------------------------------------------------------------------


def test_aether_profile_ids_lists_the_identities_a_connection_would_use():
    warp, other, server = add_aether("one"), add_aether("two"), add_trojan()
    store = ProfileStore()
    assert stack.aether_profile_ids(warp, store) == [warp.id]
    assert stack.aether_profile_ids(add_chain("c", warp, server, other), store) == [warp.id, other.id]
    assert stack.aether_profile_ids(server, store) == []
    broken = add_chain("broken", warp)
    store.remove(warp.id)
    assert stack.aether_profile_ids(broken, store) == []


def test_uses_stack():
    assert stack.uses_stack(add_aether()) and stack.uses_stack(add_chain("c", add_trojan()))
    assert not stack.uses_stack(add_trojan())


def test_the_start_timeout_can_be_raised_by_the_user(monkeypatch):
    assert stack.aether_start_timeout() == 120.0
    monkeypatch.setenv("V2RM_AETHER_START_TIMEOUT", "300")
    assert stack.aether_start_timeout() == 300.0
    monkeypatch.setenv("V2RM_AETHER_START_TIMEOUT", "nonsense")
    assert stack.aether_start_timeout() == 120.0
    monkeypatch.setenv("V2RM_AETHER_START_TIMEOUT", "1")
    assert stack.aether_start_timeout() == 5.0
