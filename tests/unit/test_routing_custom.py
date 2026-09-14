from __future__ import annotations

import pytest

from v2rm.errors import RouteValidationError
from v2rm.routing.custom import load_custom_route_plan, scaffold_if_missing
from v2rm.store import paths


def test_scaffold_creates_template_once():
    assert not paths.custom_routes_file().exists()
    scaffold_if_missing()
    assert paths.custom_routes_file().exists()
    content = paths.custom_routes_file().read_text(encoding="utf-8")

    scaffold_if_missing()  # idempotent, must not overwrite an existing file
    assert paths.custom_routes_file().read_text(encoding="utf-8") == content


def test_load_custom_route_plan_missing_file_is_empty():
    plan = load_custom_route_plan()
    assert plan.rules == []


def test_load_custom_route_plan_valid_yaml():
    paths.routes_dir().mkdir(parents=True, exist_ok=True)
    paths.custom_routes_file().write_text(
        "rules:\n"
        "  - kind: direct\n"
        "    geoip: [private]\n"
        "  - kind: block\n"
        "    domain_keyword: [ads]\n",
        encoding="utf-8",
    )
    plan = load_custom_route_plan()
    assert len(plan.rules) == 2
    assert plan.rules[0].kind == "direct"
    assert plan.rules[0].geoip == ["private"]
    assert plan.rules[1].kind == "block"
    assert plan.rules[1].domain_keyword == ["ads"]


def test_load_custom_route_plan_rejects_bad_kind():
    paths.routes_dir().mkdir(parents=True, exist_ok=True)
    paths.custom_routes_file().write_text("rules:\n  - kind: proxy\n    geoip: [ir]\n", encoding="utf-8")
    with pytest.raises(RouteValidationError):
        load_custom_route_plan()


def test_load_custom_route_plan_rejects_empty_criteria():
    paths.routes_dir().mkdir(parents=True, exist_ok=True)
    paths.custom_routes_file().write_text("rules:\n  - kind: direct\n", encoding="utf-8")
    with pytest.raises(RouteValidationError):
        load_custom_route_plan()


def test_load_custom_route_plan_rejects_non_list_field():
    paths.routes_dir().mkdir(parents=True, exist_ok=True)
    paths.custom_routes_file().write_text("rules:\n  - kind: direct\n    geoip: private\n", encoding="utf-8")
    with pytest.raises(RouteValidationError):
        load_custom_route_plan()


def test_load_custom_route_plan_rejects_invalid_yaml():
    paths.routes_dir().mkdir(parents=True, exist_ok=True)
    paths.custom_routes_file().write_text("rules: [this is not: valid: yaml:", encoding="utf-8")
    with pytest.raises(RouteValidationError):
        load_custom_route_plan()
