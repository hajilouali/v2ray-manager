"""Integration tests: the real Xray binary checks configs v2rm generates.

Nothing is started and no connection is made -- each test only runs
`xray run -test -c FILE` (the same call `v2rm connect` makes before starting a
raw/MASQUE profile). They are skipped unless you opt in:

    V2RM_INTEGRATION=1 V2RM_XRAY=/path/to/xray pytest tests/integration

`V2RM_XRAY` defaults to `xray` on PATH. Geo data (for the geosite:/geoip: rules
in routing presets and in the serverless configs) is read from
`V2RM_GEO_ASSETS` if set -- point it at the directory `v2rm route update-data`
fills, normally ~/.cache/v2rm/assets -- otherwise from next to the binary.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.fixture(scope="session")
def xray_binary() -> Path:
    if os.environ.get("V2RM_INTEGRATION") != "1":
        pytest.skip("integration test: set V2RM_INTEGRATION=1 (and V2RM_XRAY=/path/to/xray) to run")
    candidate = os.environ.get("V2RM_XRAY") or shutil.which("xray")
    if not candidate:
        pytest.skip("no Xray binary: set V2RM_XRAY=/path/to/xray (or put xray on PATH)")
    path = Path(candidate)
    if not path.is_file():
        pytest.skip(f"V2RM_XRAY={candidate} is not a file")
    return path


@pytest.fixture(scope="session")
def xray_version(xray_binary: Path) -> str:
    """E.g. '26.3.27', read from `xray version`."""
    proc = subprocess.run([str(xray_binary), "version"], capture_output=True, text=True, timeout=30)
    match = re.search(r"Xray\s+v?(\d+(?:\.\d+)+)", (proc.stdout or "") + (proc.stderr or ""))
    if not match:
        pytest.skip(f"couldn't read Xray's version from `xray version`: {proc.stdout!r}")
    return match.group(1)


@pytest.fixture(scope="session")
def assets_dir(xray_binary: Path) -> Path:
    return Path(os.environ.get("V2RM_GEO_ASSETS") or xray_binary.parent)
