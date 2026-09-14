from __future__ import annotations

from v2rm.engines.singbox.generate import build_routing_rules as singbox_rules
from v2rm.engines.xray.generate import build_routing_rules as xray_rules
from v2rm.models.enums import RoutePreset
from v2rm.routing.model import RoutePlan, RouteRule
from v2rm.routing.presets import BYPASS_CN, BYPASS_IR, GLOBAL, get_builtin


def test_get_builtin_returns_expected_presets():
    assert get_builtin(RoutePreset.GLOBAL) is GLOBAL
    assert get_builtin(RoutePreset.BYPASS_IR) is BYPASS_IR
    assert get_builtin(RoutePreset.BYPASS_CN) is BYPASS_CN


def test_global_preset_has_no_rules():
    assert GLOBAL.rules == []


def test_xray_global_preset_is_just_catch_all():
    rules = xray_rules(GLOBAL)
    assert rules == [{"type": "field", "outboundTag": "proxy"}]


def test_xray_bypass_ir_splits_domain_and_ip_into_separate_rules():
    rules = xray_rules(BYPASS_IR)
    # Every rule before the final catch-all must have EXACTLY one of
    # domain/ip populated -- never both -- otherwise Xray would AND them
    # instead of the OR the preset intends.
    for rule in rules[:-1]:
        assert ("domain" in rule) != ("ip" in rule)
    assert rules[-1] == {"type": "field", "outboundTag": "proxy"}


def test_xray_domain_rule_uses_prefixed_values():
    plan = RoutePlan(
        name="t",
        rules=[RouteRule(kind="direct", domain_suffix=["example.com"], domain_keyword=["ads"], geosite=["cn"])],
    )
    rules = xray_rules(plan)
    domain_rule = next(r for r in rules if "domain" in r)
    assert "domain:example.com" in domain_rule["domain"]
    assert "keyword:ads" in domain_rule["domain"]
    assert "geosite:cn" in domain_rule["domain"]
    assert domain_rule["outboundTag"] == "direct"


def test_singbox_never_combines_two_criteria_lists_in_one_rule():
    plan = RoutePlan(
        name="t",
        rules=[
            RouteRule(
                kind="direct",
                domain_suffix=["example.com"],
                geosite=["cn"],
                ip_cidr=["10.0.0.0/8"],
                geoip=["private"],
            )
        ],
    )
    rule_sets, rules = singbox_rules(plan)
    assert len(rules) == 4
    for r in rules:
        condition_keys = [k for k in r if k not in ("action", "outbound")]
        assert len(condition_keys) == 1
        assert r["action"] == "route"
        assert r["outbound"] == "direct"

    assert {rs["tag"] for rs in rule_sets} == {"geosite-cn", "geoip-private"}
    for rs in rule_sets:
        assert rs["type"] == "remote"
        assert rs["format"] == "binary"
        assert rs["url"].endswith(f"{rs['tag']}.srs")


def test_singbox_multiple_tags_share_one_rule_set_list():
    # geoip=["private", "cn"] on one RouteRule (BYPASS_CN) should stay ONE
    # native rule with a 2-tag rule_set list -- that's OR within the same
    # field, which is safe, unlike combining two different field types.
    _, rules = singbox_rules(BYPASS_CN)
    geoip_rules = [r for r in rules if "rule_set" in r and any(t.startswith("geoip-") for t in r["rule_set"])]
    combined = [r for r in geoip_rules if len(r["rule_set"]) == 2]
    assert combined, geoip_rules


def test_singbox_global_preset_has_no_rules():
    rule_sets, rules = singbox_rules(GLOBAL)
    assert rule_sets == []
    assert rules == []
