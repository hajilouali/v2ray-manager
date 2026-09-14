from __future__ import annotations

import requests

from v2rm.constants import DEFAULT_USER_AGENT
from v2rm.errors import FetchError


def fetch_subscription_body(
    url: str,
    user_agent: str | None = None,
    proxy: str | None = None,
    timeout: float = 20.0,
) -> str:
    headers = {"User-Agent": user_agent or DEFAULT_USER_AGENT}
    proxies = {"http": proxy, "https": proxy} if proxy else None
    try:
        resp = requests.get(url, headers=headers, proxies=proxies, timeout=timeout)
    except requests.RequestException as exc:
        raise FetchError(f"Could not fetch subscription: {exc}") from exc
    if resp.status_code != 200:
        raise FetchError(f"Subscription fetch failed: HTTP {resp.status_code}")
    return resp.text
