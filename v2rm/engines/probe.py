"""Does the installed Xray understand the newer config shapes v2rm can generate?

Answered with tiny `xray run -test` probes of configs built by the same
generator that `connect` uses, so a "supported" here means "the config v2rm
would write was accepted". Nothing is started.

The caveat that shapes the finalmask probe: Xray ignores JSON fields it does
not know, so an old core *accepts* a config with a `finalmask` block it never
reads, and a passing probe alone would prove nothing. So a second probe uses a
deliberately invalid mask type -- a core that really implements finalmask
should reject it, one that ignores the field will not.
"""

from __future__ import annotations

import copy
import json
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

from v2rm.engines.xray.generate import generate_config
from v2rm.errors import ConfigTestError
from v2rm.models.enums import Protocol, SecurityKind, TransportKind
from v2rm.models.profile import Profile, TlsSettings, TransportSettings
from v2rm.parsers import parse_link
from v2rm.process.preflight import looks_too_old, run_config_test
from v2rm.routing.presets import GLOBAL

# The shape real subscriptions use (see tests/fixtures/free_configs_sample.txt).
_FRAGMENT_MASK = {
    "type": "fragment",
    "settings": {"packets": "tlshello", "lengths": ["0", "104", "1"], "delays": ["0"], "maxSplit": "0"},
}


@dataclass(frozen=True)
class FeatureProbe:
    name: str
    supported: bool | None  # None: couldn't tell
    detail: str


def _probe_profile_masque() -> Profile:
    return parse_link("masque://masque.invalid:443?sni=masque.invalid")


def _probe_profile_finalmask(mask: dict) -> Profile:
    return Profile(
        name="v2rm-probe",
        protocol=Protocol.VLESS,
        server="probe.invalid",
        port=443,
        uuid="00000000-0000-0000-0000-000000000000",
        transport=TransportSettings(network=TransportKind.WS, path="/", finalmask={"tcp": [copy.deepcopy(mask)]}),
        tls=TlsSettings(security=SecurityKind.TLS, sni="probe.invalid"),
    )


_NOISE_PREFIXES = ("Xray rejected", "Hint:", "Xray ", "A unified platform")


def _error_line(message: str) -> str:
    """The first line of a `-test` failure that isn't the version banner or
    v2rm's own framing."""
    for line in message.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith(_NOISE_PREFIXES):
            return stripped
    return message.strip()


def _test(
    profile: Profile,
    binary: Path,
    assets_dir: Path,
    runner: Callable[..., subprocess.CompletedProcess],
) -> str | None:
    """None if `xray run -test` accepted the generated config, else the
    telling line of its error output."""
    config = generate_config(profile, GLOBAL, 10808, 10809)
    with TemporaryDirectory(prefix="v2rm-probe-") as tmp:
        path = Path(tmp) / "probe.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        try:
            run_config_test(binary, path, assets_dir, runner=runner, timeout=20)
        except ConfigTestError as exc:
            return _error_line(str(exc))
    return None


def probe_masque(
    binary: Path, assets_dir: Path, runner: Callable[..., subprocess.CompletedProcess] = subprocess.run
) -> FeatureProbe:
    error = _test(_probe_profile_masque(), binary, assets_dir, runner)
    if error is None:
        return FeatureProbe("masque", True, "a MASQUE outbound config was accepted")
    if looks_too_old(error):
        return FeatureProbe("masque", False, f"this Xray doesn't know the masque outbound ({error})")
    return FeatureProbe("masque", None, f"couldn't tell -- `xray run -test` said: {error}")


def probe_finalmask(
    binary: Path, assets_dir: Path, runner: Callable[..., subprocess.CompletedProcess] = subprocess.run
) -> FeatureProbe:
    error = _test(_probe_profile_finalmask(_FRAGMENT_MASK), binary, assets_dir, runner)
    if error is not None:
        if looks_too_old(error):
            return FeatureProbe("finalmask", False, f"this Xray doesn't know finalmask ({error})")
        return FeatureProbe("finalmask", None, f"couldn't tell -- `xray run -test` said: {error}")

    bogus = {"type": "v2rm-probe-no-such-mask", "settings": {}}
    if _test(_probe_profile_finalmask(bogus), binary, assets_dir, runner) is not None:
        return FeatureProbe("finalmask", True, "finalmask configs are accepted, and invalid masks are rejected")
    return FeatureProbe(
        "finalmask",
        None,
        "unclear -- Xray accepted an invalid mask type as well, so it probably ignores `finalmask` "
        "(an older core); `v2rm core update xray` if links using it fail",
    )


def probe_xray_features(
    binary: Path, assets_dir: Path, runner: Callable[..., subprocess.CompletedProcess] = subprocess.run
) -> list[FeatureProbe]:
    return [probe_masque(binary, assets_dir, runner), probe_finalmask(binary, assets_dir, runner)]
