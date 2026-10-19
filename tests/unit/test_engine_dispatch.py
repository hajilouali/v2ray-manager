from __future__ import annotations

import pytest

from tests.helpers import serverless_profiles
from v2rm.engines import (
    check_core_compat,
    engine_for_protocol,
    generate_config,
    needs_preflight,
    required_engine,
    resolve_engine,
    supported_protocols,
)
from v2rm.errors import CoreTooOldError
from v2rm.models.auth import ProxyAuth
from v2rm.models.enums import EngineKind, Protocol
from v2rm.models.profile import Profile
from v2rm.parsers import parse_link
from v2rm.routing.presets import GLOBAL

XRAY, SINGBOX = EngineKind.XRAY, EngineKind.SINGBOX


def raw() -> Profile:
    return serverless_profiles()[0]


def masque() -> Profile:
    return parse_link("masque://m.example.com:443?sni=s")


def trojan() -> Profile:
    return Profile(name="t", protocol=Protocol.TROJAN, server="t.example.com", port=443, password="pw")


def hysteria2() -> Profile:
    return Profile(name="h", protocol=Protocol.HYSTERIA2, server="h.example.com", port=443, password="pw")


def test_required_engine():
    assert required_engine(Protocol.RAW_XRAY) == XRAY
    assert required_engine(Protocol.MASQUE) == XRAY
    assert required_engine(Protocol.HYSTERIA2) == SINGBOX
    assert required_engine(Protocol.TUIC) == SINGBOX
    for either in (Protocol.VLESS, Protocol.VMESS, Protocol.TROJAN, Protocol.SHADOWSOCKS):
        assert required_engine(either) is None


def test_engine_for_protocol_defaults_to_xray_when_either_works():
    assert engine_for_protocol(Protocol.MASQUE) == XRAY
    assert engine_for_protocol(Protocol.RAW_XRAY) == XRAY
    assert engine_for_protocol(Protocol.TROJAN) == XRAY
    assert engine_for_protocol(Protocol.HYSTERIA2) == SINGBOX


def test_supported_protocols():
    assert {Protocol.MASQUE, Protocol.RAW_XRAY} <= supported_protocols(XRAY)
    assert not {Protocol.MASQUE, Protocol.RAW_XRAY} & supported_protocols(SINGBOX)
    assert {Protocol.HYSTERIA2, Protocol.TUIC} <= supported_protocols(SINGBOX)


# ---- resolve_engine ---------------------------------------------------------------


@pytest.mark.parametrize("preferred", [None, XRAY])
def test_raw_and_masque_use_xray_without_comment_when_xray_is_the_default_or_unset(preferred):
    assert resolve_engine(raw(), preferred) == (XRAY, None)
    assert resolve_engine(masque(), preferred) == (XRAY, None)


def test_raw_with_singbox_as_default_gets_xray_and_a_note_that_the_default_is_unchanged():
    engine, note = resolve_engine(raw(), SINGBOX)
    assert engine == XRAY
    assert note is not None
    assert "Xray-core" in note and "sing-box" in note and "raw Xray" in note
    assert "default engine is unchanged" in note


def test_masque_note_names_the_protocol():
    engine, note = resolve_engine(masque(), SINGBOX)
    assert engine == XRAY
    assert "masque" in note


def test_hysteria2_with_xray_as_default_gets_singbox():
    engine, note = resolve_engine(hysteria2(), XRAY)
    assert engine == SINGBOX
    assert "sing-box" in note and "hysteria2" in note


@pytest.mark.parametrize("preferred", [XRAY, SINGBOX])
def test_ordinary_profiles_follow_the_default(preferred):
    assert resolve_engine(trojan(), preferred) == (preferred, None)


def test_ordinary_profile_with_no_default_uses_xray():
    assert resolve_engine(trojan(), None) == (XRAY, None)


# ---- core version compatibility -------------------------------------------------------


def test_serverless_profile_needs_a_newer_core_than_26_3_27():
    with pytest.raises(CoreTooOldError) as err:
        check_core_compat(XRAY, raw(), "v26.3.27")
    assert "26.6.27" in str(err.value) and "v2rm core update xray" in str(err.value)


@pytest.mark.parametrize("installed", ["v26.6.27", "26.6.27", "v26.10.1", "v27.0.0", None, "", "not-a-version"])
def test_serverless_profile_runs_on_new_enough_or_unknown_cores(installed):
    check_core_compat(XRAY, raw(), installed)


def test_the_check_only_applies_to_raw_xray_profiles_on_xray():
    check_core_compat(SINGBOX, raw(), "v1.0.0")
    check_core_compat(XRAY, masque(), "v1.0.0")
    check_core_compat(XRAY, trojan(), "v1.0.0")


# ---- pre-flight and generate dispatch ----------------------------------------------------


def test_preflight_is_xray_only():
    assert needs_preflight(XRAY, raw())
    assert not needs_preflight(SINGBOX, raw())
    assert not needs_preflight(SINGBOX, hysteria2())
    assert not needs_preflight(XRAY, trojan())


def test_generate_config_dispatches_by_engine_and_passes_everything_through():
    notes: list[str] = []
    xray = generate_config(
        XRAY, trojan(), GLOBAL, 10808, 10809, listen_address="172.18.0.1", auth=ProxyAuth("u", "p"), notes=notes
    )
    assert xray["inbounds"][0]["protocol"] == "socks"
    assert xray["inbounds"][0]["listen"] == "172.18.0.1"
    assert xray["inbounds"][0]["settings"]["accounts"] == [{"user": "u", "pass": "p"}]

    singbox = generate_config(SINGBOX, trojan(), GLOBAL, 10808, 10809, listen_address="172.18.0.1", auth=ProxyAuth("u", "p"))
    assert singbox["inbounds"][0]["type"] == "socks"
    assert singbox["inbounds"][0]["listen"] == "172.18.0.1"
    assert singbox["inbounds"][0]["users"] == [{"username": "u", "password": "p"}]
