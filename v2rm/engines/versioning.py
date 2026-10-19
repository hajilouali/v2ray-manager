"""Core version parsing/comparison and profile version requirements.

Xray release tags look like `v26.3.27` (installed) while a config's
`"version": {"min": "26.6.27"}` has no `v`; both are compared numerically,
component by component, never as strings ("26.10.1" > "26.9.9").
"""

from __future__ import annotations

import re

from v2rm.errors import CoreTooOldError
from v2rm.models.profile import Profile

_LEADING_DIGITS = re.compile(r"\d+")


def parse_version(text: str) -> tuple[int, ...]:
    """'v26.10.17' -> (26, 10, 17). Stops at the first component without a
    leading number, so '26.6.27-rc1' -> (26, 6, 27) and garbage -> ()."""
    numbers: list[int] = []
    for piece in text.strip().lstrip("vV").split("."):
        match = _LEADING_DIGITS.match(piece)
        if not match:
            break
        numbers.append(int(match.group()))
    return tuple(numbers)


def compare_versions(a: str, b: str) -> int:
    """-1 / 0 / 1 for a <, ==, > b. Missing components count as 0."""
    pa, pb = parse_version(a), parse_version(b)
    width = max(len(pa), len(pb))
    pa += (0,) * (width - len(pa))
    pb += (0,) * (width - len(pb))
    return (pa > pb) - (pa < pb)


def raw_version_requirement(profile: Profile) -> tuple[str | None, str | None]:
    """(min, max) from a raw profile's top-level `version` block; None where
    absent or unparseable."""
    config = profile.raw_config or {}
    block = config.get("version")
    if not isinstance(block, dict):
        return None, None

    def pick(key: str) -> str | None:
        value = str(block.get(key) or "").strip()
        return value if parse_version(value) else None

    return pick("min"), pick("max")


def check_core_requirements(profile: Profile, installed: str | None) -> None:
    """Raise CoreTooOldError if the installed Xray falls outside the version
    range a raw profile declares. `installed` None (unknown) passes: Xray
    itself enforces `version` too, this just fails earlier and more readably."""
    if not installed or not parse_version(installed):
        return
    minimum, maximum = raw_version_requirement(profile)
    if minimum and compare_versions(installed, minimum) < 0:
        raise CoreTooOldError(
            f"'{profile.name}' needs Xray-core >= {minimum}, but {installed} is installed. "
            "Run `v2rm core update xray`."
        )
    if maximum and compare_versions(installed, maximum) > 0:
        raise CoreTooOldError(
            f"'{profile.name}' needs Xray-core <= {maximum}, but {installed} is installed. "
            f"Install an older release with `v2rm core install xray --version v{maximum.lstrip('vV')}`."
        )
