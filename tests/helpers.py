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
