from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from v2rm.errors import ConfigTestError
from v2rm.process.preflight import explain_xray_failure, run_config_test

BINARY = Path("/opt/v2rm/xray")
CONFIG = Path("/tmp/config.json")
ASSETS = Path("/home/u/.cache/v2rm/assets")


class FakeRunner:
    def __init__(self, returncode=0, stdout="", stderr="", raises=None):
        self.result = subprocess.CompletedProcess([], returncode, stdout, stderr)
        self.raises = raises
        self.calls: list[tuple[list[str], dict]] = []

    def __call__(self, args, **kwargs):
        self.calls.append((args, kwargs))
        if self.raises:
            raise self.raises
        return self.result


# ---- explain_xray_failure --------------------------------------------------------------


def test_output_is_shown_verbatim():
    text = "Xray 26.3.27 (Xray, Penetrates Everything.)\nFailed to start: infra/conf: some obscure problem"
    message = explain_xray_failure(text)
    assert text in message
    assert message.startswith("Xray rejected the generated config:")
    assert "Hint" not in message  # nothing recognisable, so nothing invented


def test_empty_output_is_still_a_message():
    assert "(no output)" in explain_xray_failure("  \n")


@pytest.mark.parametrize(
    "output",
    [
        "app/router: failed to load geosite: CATEGORY-IR: code not found in geosite.dat",
        "failed to open file: geoip.dat",
        "infra/conf: failed to load geodata",
    ],
)
def test_geo_problems_suggest_refreshing_the_geo_data(output):
    message = explain_xray_failure(output)
    assert output in message
    assert "v2rm route update-data --force" in message


@pytest.mark.parametrize(
    "output",
    [
        "infra/conf: unknown config id: masque",
        "infra/conf: unknown transport protocol: xhttp",
        "unknown mask type: header-custom",
    ],
)
def test_unknown_protocols_and_transports_suggest_updating_the_core(output):
    message = explain_xray_failure(output)
    assert output in message
    assert "v2rm core update xray" in message


def test_removed_features_are_explained():
    message = explain_xray_failure("transport 'quic' has been removed in this version")
    assert "has removed a feature" in message


def test_several_causes_give_several_hints():
    message = explain_xray_failure("unknown config id: x; also geosite not found")
    assert message.count("Hint:") == 2


# ---- run_config_test ------------------------------------------------------------------------


def test_a_passing_test_returns_quietly_and_runs_xray_with_the_right_arguments(monkeypatch):
    monkeypatch.setenv("SOME_OTHER_VAR", "kept")
    runner = FakeRunner()
    run_config_test(BINARY, CONFIG, ASSETS, runner=runner)

    (args, kwargs), = runner.calls
    assert args == [str(BINARY), "run", "-test", "-c", str(CONFIG)]
    assert kwargs["env"]["XRAY_LOCATION_ASSET"] == str(ASSETS)
    assert kwargs["env"]["SOME_OTHER_VAR"] == "kept"  # the environment is extended, not replaced
    assert kwargs["capture_output"] is True and kwargs["text"] is True
    assert kwargs["timeout"] == 30.0


def test_a_failing_test_raises_with_xrays_own_output():
    runner = FakeRunner(returncode=23, stdout="Xray 26.3.27\n", stderr="Failed to start: unknown config id: masque\n")
    with pytest.raises(ConfigTestError) as err:
        run_config_test(BINARY, CONFIG, ASSETS, runner=runner)
    message = str(err.value)
    assert "Failed to start: unknown config id: masque" in message
    assert "v2rm core update xray" in message


def test_none_output_streams_are_tolerated():
    runner = FakeRunner(returncode=1, stdout=None, stderr=None)
    with pytest.raises(ConfigTestError, match="no output"):
        run_config_test(BINARY, CONFIG, ASSETS, runner=runner)


def test_a_hung_test_is_reported_with_the_timeout():
    runner = FakeRunner(raises=subprocess.TimeoutExpired("xray", 5))
    with pytest.raises(ConfigTestError, match="did not finish within 5s"):
        run_config_test(BINARY, CONFIG, ASSETS, runner=runner, timeout=5)


def test_an_unrunnable_binary_is_reported():
    runner = FakeRunner(raises=FileNotFoundError("no such file"))
    with pytest.raises(ConfigTestError, match="Could not run"):
        run_config_test(BINARY, CONFIG, ASSETS, runner=runner)
