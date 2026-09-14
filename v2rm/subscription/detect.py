from __future__ import annotations

import re

import yaml

from v2rm.models.enums import SubscriptionFormat

_BASE64ISH_RE = re.compile(r"[A-Za-z0-9+/_\-]+=*")


def detect_format(text: str) -> SubscriptionFormat:
    stripped = text.strip()
    if _looks_like_clash_yaml(stripped):
        return SubscriptionFormat.CLASH_YAML
    if _looks_like_base64(stripped):
        return SubscriptionFormat.BASE64_LIST
    return SubscriptionFormat.PLAIN_LIST


def _looks_like_clash_yaml(text: str) -> bool:
    if not text:
        return False
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return False
    return isinstance(data, dict) and isinstance(data.get("proxies"), list)


def _looks_like_base64(text: str) -> bool:
    # A base64-encoded subscription body never contains a literal "://" --
    # the real share links only appear after decoding.
    if not text or "://" in text:
        return False
    compact = "".join(text.split())
    if len(compact) < 8:
        return False
    return bool(_BASE64ISH_RE.fullmatch(compact))
