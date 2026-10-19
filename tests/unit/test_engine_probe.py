from __future__ import annotations

import json
import subprocess
from pathlib import Path

from v2rm.engines.probe import FeatureProbe, probe_finalmask, probe_masque, probe_xray_features

BINARY = Path("/opt/v2rm/xray")
ASSETS = Path("/home/u/.cache/v2rm/assets")

BANNER = "Xray 26.3.27 (Xray, Penetrates Everything.) 8f2a4d1 (go1.25.1 linux/amd64)\nA unified platform for anti-censorship.\n"
KNOWN_MASKS = {"fragment", "noise"}


class FakeXray:
    """Answers `xray run -test -c FILE` like a core with the given abilities,
    judging by the config file it is actually handed."""

    def __init__(self, knows_masque=True, knows_finalmask=True, validates_masks=True, broken=None, raises=None):
        self.knows_masque = knows_masque
        self.knows_finalmask = knows_finalmask
        self.validates_masks = validates_masks
        self.broken = broken  # (returncode, output) for every run
        self.raises = raises
        self.configs: list[dict] = []
        self.commands: list[list[str]] = []

    def __call__(self, args, **kwargs):
        self.commands.append(args)
        if self.raises:
            raise self.raises
        config = json.loads(Path(args[-1]).read_text(encoding="utf-8"))
        self.configs.append(config)
        if self.broken:
            return subprocess.CompletedProcess(args, self.broken[0], self.broken[1], "")
        outbound = config["outbounds"][0]
        if outbound["protocol"] == "masque" and not self.knows_masque:
            return subprocess.CompletedProcess(
                args, 23, BANNER + "Failed to start: main: failed to load config files: [...] > infra/conf: unknown config id: masque\n", ""
            )
        masks = outbound.get("streamSettings", {}).get("finalmask", {}).get("tcp", [])
        if masks and self.knows_finalmask and self.validates_masks:
            for mask in masks:
                if mask["type"] not in KNOWN_MASKS:
                    return subprocess.CompletedProcess(args, 23, BANNER + f"Failed to start: unknown mask type: {mask['type']}\n", "")
        return subprocess.CompletedProcess(args, 0, BANNER + "Configuration OK.\n", "")


def test_a_modern_core_supports_both():
    xray = FakeXray()
    masque, finalmask = probe_xray_features(BINARY, ASSETS, xray)
    assert (masque.name, masque.supported) == ("masque", True)
    assert (finalmask.name, finalmask.supported) == ("finalmask", True)
    assert "invalid masks are rejected" in finalmask.detail


def test_the_probes_run_the_configs_v2rm_would_generate():
    xray = FakeXray()
    probe_xray_features(BINARY, ASSETS, xray)
    assert all(cmd[:4] == [str(BINARY), "run", "-test", "-c"] for cmd in xray.commands)

    masque = xray.configs[0]["outbounds"][0]
    assert masque["protocol"] == "masque"
    assert masque["streamSettings"]["network"] == "masque"
    assert masque["streamSettings"]["tlsSettings"]["alpn"] == ["h2"]

    valid, bogus = xray.configs[1]["outbounds"][0], xray.configs[2]["outbounds"][0]
    assert valid["streamSettings"]["finalmask"]["tcp"][0]["type"] == "fragment"  # the shape real subscriptions use
    assert bogus["streamSettings"]["finalmask"]["tcp"][0]["type"] == "v2rm-probe-no-such-mask"


def test_a_core_without_masque_is_reported_as_not_supporting_it():
    probe = probe_masque(BINARY, ASSETS, FakeXray(knows_masque=False))
    assert probe.supported is False
    assert "unknown config id: masque" in probe.detail  # the telling line, not the version banner
    assert "Xray 26.3.27" not in probe.detail


def test_a_core_that_ignores_finalmask_is_flagged_as_probably_too_old_not_declared_so():
    probe = probe_finalmask(BINARY, ASSETS, FakeXray(knows_finalmask=False))
    assert probe.supported is None  # a heuristic: don't claim more than it can know
    assert "probably ignores" in probe.detail and "v2rm core update xray" in probe.detail


def test_a_core_that_accepts_finalmask_but_does_not_validate_masks_is_equally_unclear():
    assert probe_finalmask(BINARY, ASSETS, FakeXray(validates_masks=False)).supported is None


def test_a_core_that_rejects_finalmask_outright_does_not_support_it():
    xray = FakeXray(broken=(23, BANNER + "Failed to start: infra/conf: unknown config id: fragment\n"))
    probe = probe_finalmask(BINARY, ASSETS, xray)
    assert probe.supported is False


def test_an_unrelated_failure_is_not_taken_for_missing_support():
    xray = FakeXray(broken=(1, "panic: runtime error: something else entirely\n"))
    for probe in probe_xray_features(BINARY, ASSETS, xray):
        assert probe.supported is None
        assert "couldn't tell" in probe.detail and "panic: runtime error" in probe.detail


def test_an_unrunnable_binary_is_not_taken_for_missing_support():
    xray = FakeXray(raises=FileNotFoundError("xray"))
    masque, finalmask = probe_xray_features(BINARY, ASSETS, xray)
    assert masque.supported is None and finalmask.supported is None
    assert "Could not run" in masque.detail


def test_probe_results_are_plain_data():
    assert FeatureProbe("x", True, "ok") == FeatureProbe("x", True, "ok")
