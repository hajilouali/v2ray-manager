from __future__ import annotations

import time
from dataclasses import dataclass

from v2rm.constants import TEST_CHUNK_SIZE, TEST_DOWNLOAD_BYTES, TEST_TIMEOUT_SECONDS, TEST_URLS
from v2rm.errors import V2rmError
from v2rm.net.proxy_client import build_proxy_session


@dataclass
class TestResult:
    ok: bool
    latency_ms: float | None = None
    throughput_mbps: float | None = None
    bytes_downloaded: int = 0
    url: str | None = None
    error: str | None = None


def run_connectivity_test(
    socks_port: int,
    urls: list[str] | None = None,
    timeout: float = TEST_TIMEOUT_SECONDS,
) -> TestResult:
    """Connect through the local SOCKS proxy and actually download a small
    file, measuring time-to-first-byte (latency) and transfer speed. Tries
    each candidate URL in turn so one unreachable test endpoint doesn't
    make an otherwise-working profile look broken."""
    session = build_proxy_session(socks_port)
    candidates = urls or TEST_URLS

    last_error = ""
    for url in candidates:
        try:
            return _download_and_measure(session, url, timeout)
        except Exception as exc:  # noqa: BLE001 - try the next candidate URL instead of failing outright
            last_error = str(exc)
            continue

    return TestResult(ok=False, error=last_error or "All test URLs failed")


def _download_and_measure(session, url: str, timeout: float) -> TestResult:
    start = time.monotonic()
    with session.get(url, stream=True, timeout=timeout) as resp:
        if hasattr(resp, "raise_for_status"):
            resp.raise_for_status()
        first_byte_time: float | None = None
        downloaded = 0
        for chunk in resp.iter_content(chunk_size=TEST_CHUNK_SIZE):
            if not chunk:
                continue
            if first_byte_time is None:
                first_byte_time = time.monotonic()
            downloaded += len(chunk)
            if downloaded >= TEST_DOWNLOAD_BYTES:
                break
        end = time.monotonic()

    if first_byte_time is None:
        raise V2rmError(f"No data received from {url}")

    latency_ms = (first_byte_time - start) * 1000
    duration = max(end - first_byte_time, 1e-6)
    throughput_mbps = (downloaded * 8 / 1_000_000) / duration

    return TestResult(
        ok=True, latency_ms=latency_ms, throughput_mbps=throughput_mbps, bytes_downloaded=downloaded, url=url
    )
