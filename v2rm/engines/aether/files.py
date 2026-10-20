"""The files Aether keeps for a profile: its WARP identities and its last-working-gateway cache.

Aether derives all of them from the one base path v2rm gives it (`AETHER_CONFIG`), naming each
by inserting a suffix before the extension -- `aether.toml` -> `aether-masque.toml`,
`aether-masque-gool.toml`, `aether-secondary.toml`, `aether-masque-lastconn.toml`. This module
knows those names (to say whether a profile has registered yet, show the remembered gateways,
and forget them) without ever reading the keys themselves.
"""

from __future__ import annotations

import contextlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from v2rm.models.aether import AetherMode
from v2rm.store import paths

BASE_NAME = "aether.toml"


def config_path(profile_id: str) -> Path:
    """The base identity path handed to Aether for this profile."""
    return paths.aether_profile_dir(profile_id) / BASE_NAME


def derive_sibling(base: Path, suffix: str) -> Path:
    """Aether's own naming rule: `<stem>-<suffix><.ext>` in the same folder; a name without an
    extension just gets `-<suffix>` appended."""
    name = base.name
    dot = name.rfind(".")
    derived = f"{name[:dot]}-{suffix}{name[dot:]}" if dot > 0 else f"{name}-{suffix}"
    return base.with_name(derived)


def identity_files(base: Path, mode: AetherMode) -> list[Path]:
    """The identity files this mode needs (each is registered with Cloudflare the first time)."""
    masque = derive_sibling(base, "masque")
    if mode == AetherMode.MASQUE:
        return [masque]
    if mode == AetherMode.WG:
        return [base]
    if mode == AetherMode.GOOL:
        return [masque, derive_sibling(masque, "gool")]
    if mode == AetherMode.GOOL_CLASSIC:
        return [base, derive_sibling(base, "secondary")]
    return [masque, derive_sibling(masque, "secondary")]  # MIM


def identity_state(base: Path, mode: AetherMode) -> tuple[int, int]:
    """(registered, needed): how many of the mode's identities exist already."""
    files = identity_files(base, mode)
    return sum(1 for f in files if f.is_file()), len(files)


def lastconn_file(base: Path, mode: AetherMode) -> Path | None:
    """The cache of the last working gateways, for the modes Aether keeps one for."""
    if mode in (AetherMode.MASQUE, AetherMode.GOOL):
        return derive_sibling(derive_sibling(base, "masque"), "lastconn")
    if mode == AetherMode.WG:
        return derive_sibling(base, "lastconn")
    return None


@dataclass
class LastGateways:
    peer: str = ""
    carrier: str = ""
    profile: str = ""
    recent: list[str] = field(default_factory=list)


_KEY_VALUE = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$')
_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')


def _unquote(text: str) -> str:
    return text.replace('\\"', '"').replace("\\\\", "\\")


def read_last_gateways(path: Path | None) -> LastGateways | None:
    """The remembered gateways, or None if there is no usable cache. Only the shapes Aether
    writes are read (strings, and one array of strings), so no TOML library is needed."""
    if path is None:
        return None
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None

    values: dict[str, str] = {}
    arrays: dict[str, list[str]] = {}
    lines = iter(text.splitlines())
    for line in lines:
        match = _KEY_VALUE.match(line)
        if not match:
            continue
        key, rest = match.groups()
        if rest.startswith("["):
            body = rest
            while "]" not in body:
                nxt = next(lines, None)
                if nxt is None:
                    break
                body += " " + nxt
            arrays[key] = [_unquote(m) for m in _QUOTED.findall(body)]
        else:
            quoted = _QUOTED.match(rest)
            if quoted:
                values[key] = _unquote(quoted.group(1))

    if not values.get("peer") and not arrays.get("recent"):
        return None
    return LastGateways(
        peer=values.get("peer", ""),
        carrier=values.get("carrier", ""),
        profile=values.get("profile", ""),
        recent=arrays.get("recent", []),
    )


def forget_last_gateways(path: Path | None) -> bool:
    """Delete the cache so the next start scans afresh. True if there was one."""
    if path is None or not path.is_file():
        return False
    with contextlib.suppress(OSError):
        path.unlink()
        return True
    return False


def remove_profile_state(profile_id: str) -> bool:
    """Delete everything Aether kept for a profile (identities included). True if anything went."""
    import shutil

    directory = paths.aether_profile_dir(profile_id)
    if not directory.exists():
        return False
    shutil.rmtree(directory, ignore_errors=True)
    return True
