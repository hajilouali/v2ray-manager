"""`xray run -test` against the configs v2rm generates (see conftest.py to enable).

A failing test here means the real Xray rejected a config v2rm believes is
valid. Unit tests cover the structure; only the real binary can say whether
Xray accepts it.
"""

from __future__ import annotations

import json
import re

import pytest

from tests.helpers import free_links, link_with, serverless_profiles
from v2rm.engines.probe import probe_finalmask, probe_masque
from v2rm.engines.versioning import compare_versions
from v2rm.engines.xray.generate import generate_config
from v2rm.errors import ConfigTestError
from v2rm.models.auth import ProxyAuth
from v2rm.parsers import parse_link
from v2rm.process.preflight import run_config_test
from v2rm.routing.presets import BYPASS_IR, GLOBAL

pytestmark = pytest.mark.integration

_GEO_PROBLEM = re.compile(r"geosite|geoip|geodata", re.IGNORECASE)
LISTEN_ADDRESSES = ["127.0.0.1", "0.0.0.0", "172.18.0.1"]


def check(xray_binary, assets_dir, tmp_path, config: dict) -> None:
    """Fail with Xray's own message if it rejects `config`. A complaint about
    geo data is skipped instead: it says the installed geo files lack a tag,
    not that the generated structure is wrong."""
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    try:
        run_config_test(xray_binary, path, assets_dir)
    except ConfigTestError as exc:
        if _GEO_PROBLEM.search(str(exc)):
            pytest.skip(f"geo data in {assets_dir} lacks something this config uses:\n{exc}")
        pytest.fail(str(exc))


def accepted(xray_binary, assets_dir, tmp_path, profile, preset=GLOBAL, listen="127.0.0.1", auth=None) -> None:
    config = generate_config(profile, preset, 10808, 10809, listen_address=listen, auth=auth)
    check(xray_binary, assets_dir, tmp_path, config)


# ---- the harness itself -------------------------------------------------------------------------------


def test_the_harness_rejects_a_broken_config(xray_binary, assets_dir, tmp_path):
    path = tmp_path / "broken.json"
    path.write_text(json.dumps({"outbounds": [{"protocol": "definitely-not-a-protocol", "settings": {}}]}))
    with pytest.raises(ConfigTestError):
        run_config_test(xray_binary, path, assets_dir)


# ---- ordinary profiles: the baseline every Xray should accept ------------------------------------------------


@pytest.mark.parametrize(
    "link",
    [
        "trojan://pw@t.example.com:443?security=tls&sni=t.example.com#trojan",
        "vless://11111111-2222-3333-4444-555555555555@v.example.com:443?security=tls&sni=v.example.com&type=ws&path=%2Fws&host=v.example.com#vless-ws",
        "vless://11111111-2222-3333-4444-555555555555@r.example.com:443?security=reality&sni=hide.example.com&pbk=cmV2ZXJzZS1zdGFuZGlu-bm90LWEtcmVhbC1rZXktMTIzNDU2&sid=ab&fp=chrome&flow=xtls-rprx-vision#reality",
        "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@s.example.com:8388#ss",
    ],
    ids=["trojan", "vless-ws", "vless-reality", "shadowsocks"],
)
def test_ordinary_profiles_are_accepted(xray_binary, assets_dir, tmp_path, link):
    accepted(xray_binary, assets_dir, tmp_path, parse_link(link))


def test_a_routing_preset_with_geo_rules_is_accepted(xray_binary, assets_dir, tmp_path):
    profile = parse_link("trojan://pw@t.example.com:443?security=tls#t")
    accepted(xray_binary, assets_dir, tmp_path, profile, preset=BYPASS_IR)


@pytest.mark.parametrize("listen", LISTEN_ADDRESSES)
def test_inbounds_on_each_kind_of_listen_address_and_with_a_login(xray_binary, assets_dir, tmp_path, listen):
    profile = parse_link("trojan://pw@t.example.com:443?security=tls#t")
    accepted(xray_binary, assets_dir, tmp_path, profile, listen=listen)
    accepted(xray_binary, assets_dir, tmp_path, profile, listen=listen, auth=ProxyAuth("demo", "p@ss:w/rd"))


# ---- raw Xray configs (the real "serverless" subscription) --------------------------------------------------------


@pytest.mark.parametrize("listen", LISTEN_ADDRESSES)
def test_the_real_serverless_configs_are_accepted_after_the_inbound_rewrite(
    xray_binary, assets_dir, tmp_path, xray_version, listen
):
    # The configs declare version.min 26.6.27; an older Xray refuses them itself.
    for profile in serverless_profiles():
        minimum = profile.raw_config["version"]["min"]
        if compare_versions(xray_version, minimum) < 0:
            pytest.skip(f"Xray {xray_version} is older than the config's own version.min {minimum}")
        accepted(xray_binary, assets_dir, tmp_path, profile, listen=listen)


def test_the_serverless_configs_are_accepted_with_a_proxy_login(xray_binary, assets_dir, tmp_path, xray_version):
    for profile in serverless_profiles():
        if compare_versions(xray_version, profile.raw_config["version"]["min"]) < 0:
            pytest.skip(f"Xray {xray_version} is older than the config's own version.min")
        accepted(xray_binary, assets_dir, tmp_path, profile, listen="172.18.0.1", auth=ProxyAuth("demo", "pw"))


# ---- MASQUE -----------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "link",
    [
        "masque://m.example.com:443?sni=front.example.com",
        "masque://alice:s3cret@m.example.com:8443?sni=front.example.com&alpn=h2&path=%2Fmasque&host=h.example.com&fp=chrome",
        "masque://m.example.com:443?sni=front.example.com&alpn=h3",
        "masque://m.example.com:443?sni=s.example.com&headers=%7B%22X-Token%22%3A%22abc%22%7D&dns=1.1.1.1,8.8.8.8",
    ],
    ids=["minimal", "user-path-host", "h3", "headers-dns"],
)
def test_masque_profiles_are_accepted(xray_binary, assets_dir, tmp_path, link):
    if probe_masque(xray_binary, assets_dir).supported is False:
        pytest.skip("this Xray predates the MASQUE outbound")
    accepted(xray_binary, assets_dir, tmp_path, parse_link(link))


# ---- extended link parameters (real links from the Free-Configs sample) --------------------------------------------------


def _real_links():
    return [(index, link) for index, link in enumerate(free_links())]


@pytest.mark.parametrize(("index", "link"), _real_links(), ids=[f"link-{i}" for i, _ in _real_links()])
def test_every_real_sample_link_is_accepted(xray_binary, assets_dir, tmp_path, index, link):
    profile = parse_link(link)
    if profile.transport.finalmask and probe_finalmask(xray_binary, assets_dir).supported is False:
        pytest.skip("this Xray predates finalmask")
    accepted(xray_binary, assets_dir, tmp_path, profile)


def test_the_post_quantum_link_is_accepted(xray_binary, assets_dir, tmp_path):
    profile = parse_link(link_with(lambda q, _: q.get("encryption", "").startswith("mlkem")))
    if profile.transport.finalmask and probe_finalmask(xray_binary, assets_dir).supported is False:
        pytest.skip("this Xray predates finalmask")
    accepted(xray_binary, assets_dir, tmp_path, profile)
