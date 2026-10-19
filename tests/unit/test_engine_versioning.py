from __future__ import annotations

import pytest

from tests.helpers import serverless_profiles
from v2rm.engines.versioning import (
    check_core_requirements,
    compare_versions,
    parse_version,
    raw_version_requirement,
)
from v2rm.errors import CoreTooOldError
from v2rm.models.enums import Protocol
from v2rm.models.profile import Profile


def raw(version) -> Profile:
    config: dict = {"outbounds": []}
    if version is not None:
        config["version"] = version
    return Profile(name="cfg", protocol=Protocol.RAW_XRAY, raw_config=config)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("v26.3.27", (26, 3, 27)),
        ("26.6.27", (26, 6, 27)),
        ("V1.2", (1, 2)),
        (" v26.10.17 ", (26, 10, 17)),
        ("26.6.27-rc1", (26, 6, 27)),
        ("1.8.x", (1, 8)),
        ("garbage", ()),
        ("", ()),
    ],
)
def test_parse_version(text, expected):
    assert parse_version(text) == expected


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("26.10.1", "26.9.9", 1),  # numeric, not lexicographic
        ("v26.3.27", "26.3.27", 0),  # the leading v doesn't matter
        ("26.3", "26.3.0", 0),  # missing components count as zero
        ("1.0", "1.0.1", -1),
        ("v26.3.27", "26.6.27", -1),
    ],
)
def test_compare_versions(a, b, expected):
    assert compare_versions(a, b) == expected


def test_the_real_serverless_profile_requires_26_6_27():
    assert raw_version_requirement(serverless_profiles()[0]) == ("26.6.27", None)


def test_requirement_reads_min_and_max_and_ignores_the_unusable():
    assert raw_version_requirement(raw({"min": "1.8.0", "max": "v2.0.0"})) == ("1.8.0", "v2.0.0")
    assert raw_version_requirement(raw({"min": "soon"})) == (None, None)
    assert raw_version_requirement(raw("26.6.27")) == (None, None)  # not a block
    assert raw_version_requirement(raw(None)) == (None, None)
    assert raw_version_requirement(Profile(name="x", protocol=Protocol.RAW_XRAY)) == (None, None)


def test_too_old_core_is_rejected_with_the_update_command():
    with pytest.raises(CoreTooOldError) as err:
        check_core_requirements(serverless_profiles()[0], "v26.3.27")
    message = str(err.value)
    assert "needs Xray-core >= 26.6.27" in message
    assert "v26.3.27 is installed" in message
    assert "v2rm core update xray" in message


def test_new_enough_core_passes_whatever_the_spelling():
    profile = serverless_profiles()[0]
    for installed in ("v26.6.27", "26.6.27", "v26.7.1", "v26.10.0"):
        check_core_requirements(profile, installed)


def test_a_core_newer_than_the_declared_maximum_is_rejected_with_the_downgrade_command():
    with pytest.raises(CoreTooOldError) as err:
        check_core_requirements(raw({"max": "v1.8.9"}), "v1.9.0")
    message = str(err.value)
    assert "needs Xray-core <= v1.8.9" in message
    assert "v2rm core install xray --version v1.8.9" in message


def test_an_unknown_installed_version_is_not_a_failure():
    profile = serverless_profiles()[0]
    check_core_requirements(profile, None)
    check_core_requirements(profile, "")
    check_core_requirements(profile, "dev-build")


def test_a_profile_without_a_version_block_never_fails():
    check_core_requirements(raw(None), "v0.0.1")
