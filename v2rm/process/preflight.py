"""Pre-flight validation of a generated Xray config: `xray run -test -c FILE`.

Raw and MASQUE profiles (and anything using newer-core-only features) are
validated before the engine is started, so a failure is reported with Xray's
own message plus a hint, instead of as a process that exits a moment after
launch.
"""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Callable
from pathlib import Path

from v2rm.engines.versioning import UPDATE_XRAY_HINT
from v2rm.errors import ConfigTestError

_GEO_RE = re.compile(r"geosite|geoip|geodata", re.IGNORECASE)
_TOO_OLD_RE = re.compile(
    r"unknown config id|unknown transport protocol|unknown protocol|unknown mask|"
    r"unknown (?:network|security)|not (?:yet )?supported in this version",
    re.IGNORECASE,
)
_REMOVED_RE = re.compile(r"removed|no longer supported", re.IGNORECASE)


def looks_too_old(output: str) -> bool:
    """Whether Xray's error output reads like "this core doesn't know that"."""
    return bool(_TOO_OLD_RE.search(output))


def explain_xray_failure(output: str) -> str:
    """Xray's error output verbatim, plus a hint for the recurring causes."""
    output = output.strip() or "(no output)"
    hints: list[str] = []
    if _GEO_RE.search(output):
        hints.append(
            "A geosite:/geoip: tag (or the geo data file itself) couldn't be loaded. "
            "Run `v2rm route update-data --force` to refresh v2rm's geo data; if the tag still "
            "isn't found, this config expects different geo data than the default."
        )
    if looks_too_old(output):
        hints.append(f"Your Xray-core looks too old for this config. {UPDATE_XRAY_HINT}")
    if _REMOVED_RE.search(output):
        hints.append(
            "This Xray-core release has removed a feature the config uses; the config needs "
            "updating (or an older core: `v2rm core install xray --version vX.Y.Z`)."
        )
    message = f"Xray rejected the generated config:\n{output}"
    if hints:
        message += "\n\n" + "\n".join(f"Hint: {h}" for h in hints)
    return message


def run_config_test(
    binary: Path,
    config_path: Path,
    assets_dir: Path,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
    timeout: float = 30.0,
) -> None:
    """Run `<binary> run -test -c <config>` with XRAY_LOCATION_ASSET pointing at
    v2rm's geo assets; raise ConfigTestError (with Xray's output) on failure."""
    env = dict(os.environ)
    env["XRAY_LOCATION_ASSET"] = str(assets_dir)
    try:
        proc = runner(
            [str(binary), "run", "-test", "-c", str(config_path)],
            capture_output=True,
            text=True,
            env=env,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise ConfigTestError(f"`{binary.name} run -test` did not finish within {timeout:g}s") from exc
    except OSError as exc:
        raise ConfigTestError(f"Could not run `{binary} run -test`: {exc}") from exc

    if proc.returncode != 0:
        raise ConfigTestError(explain_xray_failure((proc.stdout or "") + (proc.stderr or "")))
