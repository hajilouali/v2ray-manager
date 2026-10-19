"""Raw Xray profiles: complete Xray configs stored verbatim.

Some configs have no server at all -- e.g. "serverless" DPI-evasion configs
that only use direct/block/dns outbounds with TLS-hello fragmentation. They
can't be a normal Profile (no server/port), so each one becomes a
`Protocol.RAW_XRAY` profile holding the whole JSON in `raw_config`.
"""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

from v2rm.errors import ParseError
from v2rm.models.enums import Protocol
from v2rm.models.profile import Profile, canonical_json


def is_raw_config(obj: Any) -> bool:
    return isinstance(obj, dict) and isinstance(obj.get("outbounds"), list)


def validate_raw_config(obj: Any) -> dict[str, Any]:
    """Raise ParseError unless `obj` is a JSON object with an `outbounds` list --
    the minimum for it to be an Xray config rather than arbitrary JSON."""
    if not isinstance(obj, dict):
        raise ParseError("An Xray config must be a JSON object")
    if not isinstance(obj.get("outbounds"), list):
        raise ParseError("Xray config has no 'outbounds' list")
    return obj


def raw_profile_name(config: dict[str, Any]) -> str:
    remarks = str(config.get("remarks") or "").strip()
    if remarks:
        return remarks
    digest = hashlib.sha256(canonical_json(config).encode("utf-8")).hexdigest()[:8]
    return f"raw-xray-{digest}"


def profile_from_config(config: Any) -> Profile:
    validate_raw_config(config)
    return Profile(
        name=raw_profile_name(config),
        protocol=Protocol.RAW_XRAY,
        raw_config=copy.deepcopy(config),
    )


def parse_json_text(text: str) -> Any:
    try:
        return json.loads(text.lstrip("﻿"))
    except json.JSONDecodeError as exc:
        raise ParseError(f"Not valid JSON: {exc}") from exc


def is_xray_json_body(text: str) -> bool:
    """True if `text` is one Xray config object, or a non-empty array of them
    (a JSON subscription body). Cheap pre-check first so a huge base64 blob
    isn't fed to the JSON parser."""
    stripped = text.lstrip("﻿").strip()
    if not stripped or stripped[0] not in "{[":
        return False
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        return False
    if isinstance(data, dict):
        return is_raw_config(data)
    return isinstance(data, list) and bool(data) and all(is_raw_config(item) for item in data)


def parse_xray_json(text: str) -> tuple[list[Profile], list[tuple[str, str]]]:
    """Parse one config object or an array of them into raw profiles.

    Returns (profiles, errors) like parse_links: an invalid array item is
    reported, the rest still import. Input that isn't JSON at all raises."""
    data = parse_json_text(text)
    items = data if isinstance(data, list) else [data]
    if not items:
        raise ParseError("The JSON array is empty")

    profiles: list[Profile] = []
    errors: list[tuple[str, str]] = []
    for index, item in enumerate(items, start=1):
        label = str(item.get("remarks")) if isinstance(item, dict) and item.get("remarks") else f"item {index}"
        try:
            profiles.append(profile_from_config(item))
        except ParseError as exc:
            errors.append((label, str(exc)))
    return profiles, errors
