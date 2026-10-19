"""Comment-header metadata in subscription bodies.

Plain link-list subscriptions often start with a block of `#` comments, some
of which are machine-readable (the convention used by several clients):

    #profile-title: Free-Configs
    #profile-update-interval: 1
    #profile-web-page-url: https://github.com/patterniha/Free-Configs

followed by free-text comments (which commonly contain URLs, i.e. "://").
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass

_HEADER_RE = re.compile(r"^#\s*(profile-[a-z-]+)\s*:\s*(.*?)\s*$", re.IGNORECASE)


@dataclass
class SubscriptionMeta:
    title: str | None = None
    update_interval_hours: float | None = None
    web_page_url: str | None = None


def strip_comment_lines(text: str) -> str:
    """The body without its `#` comment lines. Needed before deciding whether
    what's left is base64: the comment block contains URLs, which would
    otherwise look like a link list."""
    return "\n".join(line for line in text.lstrip("﻿").splitlines() if not line.lstrip().startswith("#"))


def _decode_title(value: str) -> str:
    # Some providers send the title as "base64:<payload>".
    if value.lower().startswith("base64:"):
        payload = value[len("base64:") :].strip()
        try:
            return base64.b64decode(payload + "=" * (-len(payload) % 4)).decode("utf-8").strip()
        except (binascii.Error, ValueError):
            return value
    return value


def parse_meta(text: str) -> SubscriptionMeta:
    meta = SubscriptionMeta()
    for line in text.lstrip("﻿").splitlines():
        match = _HEADER_RE.match(line.strip())
        if not match:
            continue
        key, value = match.group(1).lower(), match.group(2)
        if not value:
            continue
        if key == "profile-title":
            meta.title = _decode_title(value) or None
        elif key == "profile-update-interval":
            try:
                hours = float(value)
            except ValueError:
                continue
            if hours > 0:
                meta.update_interval_hours = hours
        elif key == "profile-web-page-url":
            meta.web_page_url = value
    return meta
