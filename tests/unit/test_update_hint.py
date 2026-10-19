"""Every "your Xray is too old" message must point at a command that can actually fix it.
Xray-core publishes its newest builds only as pre-releases, so a bare `core update xray`
would install the old stable one again -- the hint has to say `--pre`."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tests.helpers import serverless_profiles
from v2rm.engines.probe import probe_finalmask
from v2rm.engines.versioning import UPDATE_XRAY_HINT, check_core_requirements
from v2rm.errors import CoreTooOldError
from v2rm.process.preflight import explain_xray_failure


def test_the_hint_names_the_command_and_why():
    assert "v2rm core update xray --pre" in UPDATE_XRAY_HINT
    assert "pre-releases" in UPDATE_XRAY_HINT


def test_a_config_that_needs_a_newer_core():
    with pytest.raises(CoreTooOldError) as err:
        check_core_requirements(serverless_profiles()[0], "v26.3.27")
    assert UPDATE_XRAY_HINT in str(err.value)


def test_xray_rejecting_an_unknown_protocol():
    assert UPDATE_XRAY_HINT in explain_xray_failure("infra/conf: unknown config id: masque")


def test_the_finalmask_probe_when_the_core_ignores_it():
    class IgnoresFinalmask:
        def __call__(self, args, **kwargs):
            return subprocess.CompletedProcess(args, 0, "Configuration OK.\n", "")

    probe = probe_finalmask(Path("/opt/xray"), Path("/tmp/assets"), IgnoresFinalmask())
    assert probe.supported is None
    assert "v2rm core update xray --pre" in probe.detail
