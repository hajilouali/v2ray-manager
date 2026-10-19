from __future__ import annotations

import json
from pathlib import Path
from typing import Any

FIXTURES = Path(__file__).parent / "fixtures"


def read_fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def load_json_fixture(name: str) -> Any:
    return json.loads(read_fixture(name))


def free_links() -> list[str]:
    """The non-comment lines of the real Free-Configs sample, in file order."""
    return [
        line.strip()
        for line in read_fixture("free_configs_sample.txt").splitlines()
        if line.strip() and not line.startswith("#")
    ]


def link_with(predicate) -> str:
    """The first real sample link whose parsed query satisfies predicate(q, link)."""
    from urllib.parse import parse_qs, urlsplit

    for link in free_links():
        q = {k: v[0] for k, v in parse_qs(urlsplit(link).query, keep_blank_values=True).items()}
        if predicate(q, link):
            return link
    raise AssertionError("no sample link matches")


def serverless_profiles():
    """The two raw profiles parsed from the real serverless body."""
    from v2rm.parsers.raw import parse_xray_json

    profiles, errors = parse_xray_json(read_fixture("serverless_subscription.json"))
    assert not errors
    return profiles
