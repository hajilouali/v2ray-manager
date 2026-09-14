from __future__ import annotations

from typing import Any

import yaml

from v2rm.errors import RouteValidationError
from v2rm.routing.model import RoutePlan, RouteRule
from v2rm.store import paths

_TEMPLATE = """\
# v2rm custom routing rules.
#
# Each rule sends matching traffic to "direct" (bypass the proxy) or
# "block" (drop it). Traffic that matches nothing here goes through the
# proxy, same as the "global" preset. Rules are evaluated top to bottom.
#
# Fields (all optional -- use whichever apply to a rule):
#   domain_suffix:  ["example.com"]       # exact domain + all subdomains
#   domain_keyword: ["ads"]               # substring match anywhere in the domain
#   geosite:        ["category-ir"]       # geosite categories (sing-box rule-set / Xray .dat)
#   ip_cidr:        ["10.0.0.0/8"]        # literal IP ranges
#   geoip:          ["ir", "private"]     # GeoIP country/category codes
#
# Example:
# rules:
#   - kind: direct
#     geoip: ["private"]
#   - kind: direct
#     domain_suffix: ["example.com"]
#     geosite: ["category-ir"]
#   - kind: block
#     domain_keyword: ["ads"]

rules: []
"""

_VALID_KINDS = {"direct", "block"}
_LIST_FIELDS = ("domain_suffix", "domain_keyword", "geosite", "ip_cidr", "geoip")


def scaffold_if_missing() -> None:
    path = paths.custom_routes_file()
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_TEMPLATE, encoding="utf-8")


def load_custom_route_plan() -> RoutePlan:
    path = paths.custom_routes_file()
    if not path.exists():
        return RoutePlan(name="custom", rules=[])

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise RouteValidationError(f"Invalid YAML in {path}: {exc}") from exc

    raw_rules = data.get("rules") or []
    if not isinstance(raw_rules, list):
        raise RouteValidationError(f"'rules' in {path} must be a list")

    rules = [_parse_rule(entry, i, path) for i, entry in enumerate(raw_rules)]
    return RoutePlan(name="custom", rules=rules)


def _parse_rule(entry: Any, index: int, path) -> RouteRule:
    if not isinstance(entry, dict):
        raise RouteValidationError(f"Rule #{index + 1} in {path} must be a mapping")

    kind = str(entry.get("kind", "")).strip()
    if kind not in _VALID_KINDS:
        raise RouteValidationError(
            f"Rule #{index + 1} in {path} has kind='{kind}'; must be 'direct' or 'block'"
        )

    values: dict[str, list[str]] = {}
    for field_name in _LIST_FIELDS:
        raw = entry.get(field_name) or []
        if not isinstance(raw, list):
            raise RouteValidationError(f"Rule #{index + 1} in {path}: '{field_name}' must be a list")
        values[field_name] = [str(v) for v in raw]

    rule = RouteRule(kind=kind, **values)
    if not (rule.has_domain_criteria() or rule.has_ip_criteria()):
        raise RouteValidationError(
            f"Rule #{index + 1} in {path} has no criteria (domain/ip fields are all empty)"
        )
    return rule
