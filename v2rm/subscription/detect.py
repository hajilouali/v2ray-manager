from __future__ import annotations

import re

import yaml

from v2rm.models.enums import SubscriptionFormat
from v2rm.parsers.raw import is_xray_json_body
from v2rm.subscription.meta import strip_comment_lines

_BASE64ISH_RE = re.compile(r"[A-Za-z0-9+/_\-]+=*")


def detect_format(text: str) -> SubscriptionFormat:
    stripped = text.lstrip("﻿").strip()

    # Xray JSON first: a body that parses as JSON is never one of the others,
    # and the cheap first-character check keeps big non-JSON bodies away from
    # the JSON parser.
    if is_xray_json_body(stripped):
        return SubscriptionFormat.XRAY_JSON

    # Clash YAML necessarily contains "proxies:"; checking that first avoids
    # running the (slow) YAML parser over a several-hundred-link list.
    if "proxies:" in stripped and _looks_like_clash_yaml(stripped):
        return SubscriptionFormat.CLASH_YAML

    # Judge base64-ness on the body without its comment header, which holds
    # URLs ("://") and would make an encoded body look like a link list.
    body = strip_comment_lines(stripped).strip()
    if _looks_like_base64(body):
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
