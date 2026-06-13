"""Shared async HTTP client with per-API rate limiters and retry logic."""

from __future__ import annotations

import asyncio
from typing import Optional

import httpx
from aiolimiter import AsyncLimiter

from config import settings
from utils.logger import get_logger
from utils.rate_tracker import RateLimitTracker

log = get_logger("http")


# ── Per-API rate limiters ─────────────────────────────────────────────────────

# VirusTotal free tier: 4 requests / minute
vt_limiter = AsyncLimiter(settings.vt_rpm, 60)

# AbuseIPDB free tier: ~1000 / day → ~15 / min conservative
abuseipdb_limiter = AsyncLimiter(settings.abuseipdb_rpm, 60)

# Shodan: ~1 req/sec for paid plans
shodan_limiter = AsyncLimiter(settings.shodan_rpm, 60)

# GreyNoise: ~30 req/min
greynoise_limiter = AsyncLimiter(30, 60)

# AlienVault: ~30 req/min
alienvault_limiter = AsyncLimiter(30, 60)


# ── Client factory ────────────────────────────────────────────────────────────


def create_client(timeout: Optional[int] = None) -> httpx.AsyncClient:
    """Create a configured ``httpx.AsyncClient``."""
    return httpx.AsyncClient(
        timeout=httpx.Timeout(timeout or settings.http_timeout),
        follow_redirects=True,
        headers={"User-Agent": "ip-intel/1.0"},
    )


# ── Rate-limited request helper ──────────────────────────────────────────────


async def rate_limited_get(
    client: httpx.AsyncClient,
    url: str,
    limiter: AsyncLimiter,
    *,
    headers: Optional[dict] = None,
    params: Optional[dict] = None,
    max_retries: int = 3,
    tracker: Optional[RateLimitTracker] = None,
) -> httpx.Response:
    """Perform a GET request respecting the given rate limiter.

    On HTTP 429 (Too Many Requests), retries with exponential back-off.
    If a ``RateLimitTracker`` is provided, it will be consulted before
    making requests and updated from response headers.
    """
    # Check budget guard before attempting
    if tracker:
        wait = await tracker.wait_if_needed()
        if wait > 0:
            log.info("Budget guard waited %.1fs for %s", wait, tracker.provider)

    for attempt in range(1, max_retries + 1):
        async with limiter:
            try:
                response = await client.get(url, headers=headers, params=params)

                # Update tracker from response headers
                if tracker:
                    tracker.update_from_headers(dict(response.headers))
                    tracker.consume()

                if response.status_code == 429:
                    if tracker:
                        tracker.update_from_429(dict(response.headers))
                        wait = await tracker.wait_if_needed()
                        if wait > 0:
                            continue
                    # Fallback exponential backoff
                    wait = 2 ** attempt
                    log.warning(
                        "Rate-limited on %s (attempt %d/%d) — retrying in %ds",
                        url,
                        attempt,
                        max_retries,
                        wait,
                    )
                    await asyncio.sleep(wait)
                    continue

                response.raise_for_status()
                return response

            except httpx.HTTPStatusError:
                raise
            except httpx.HTTPError as exc:
                if attempt == max_retries:
                    raise
                wait = 2 ** attempt
                log.warning(
                    "HTTP error on %s: %s (attempt %d/%d) — retrying in %ds",
                    url,
                    exc,
                    attempt,
                    max_retries,
                    wait,
                )
                await asyncio.sleep(wait)

    # Should not reach here, but satisfy the type checker
    raise httpx.HTTPError(f"Max retries ({max_retries}) exceeded for {url}")
