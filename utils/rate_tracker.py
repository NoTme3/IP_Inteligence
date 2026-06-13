"""API rate-limit budget tracker — prevents exhaustion and provides wait estimates.

Parses standard rate-limit response headers (X-RateLimit-Remaining, X-RateLimit-Reset)
returned by VirusTotal, AbuseIPDB, and GreyNoise to maintain per-provider budget awareness.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Optional

from utils.logger import get_logger

log = get_logger("rate_tracker")


@dataclass
class RateLimitTracker:
    """Tracks remaining API budget for a single provider.

    Attributes
    ----------
    provider:
        Human-readable name of the API provider.
    default_rpm:
        Default requests-per-minute budget if headers are absent.
    remaining:
        Estimated requests remaining in the current window.
    reset_at:
        Unix timestamp when the budget window resets.
    window_seconds:
        Length of the rate-limit window in seconds.
    last_wait_seconds:
        Duration of the most recent enforced wait (for SSE reporting).
    """

    provider: str
    default_rpm: int = 60
    remaining: Optional[int] = None
    reset_at: float = 0.0
    window_seconds: float = 60.0
    last_wait_seconds: float = 0.0
    _waiting: bool = field(default=False, repr=False)

    @property
    def is_exhausted(self) -> bool:
        """True when budget is depleted and the window hasn't reset yet."""
        if self.remaining is not None and self.remaining <= 0:
            return time.time() < self.reset_at
        return False

    @property
    def wait_time(self) -> float:
        """Seconds until the budget resets. 0 if not exhausted."""
        if self.is_exhausted:
            return max(0.0, self.reset_at - time.time())
        return 0.0

    def update_from_headers(self, headers: dict) -> None:
        """Parse rate-limit headers from an API response.

        Supported headers (case-insensitive):
            X-RateLimit-Remaining / x-ratelimit-remaining
            X-RateLimit-Reset     / x-ratelimit-reset
            Retry-After           / retry-after
        """
        lower = {k.lower(): v for k, v in headers.items()}

        remaining = lower.get("x-ratelimit-remaining")
        if remaining is not None:
            try:
                self.remaining = int(remaining)
            except (ValueError, TypeError):
                pass

        reset = lower.get("x-ratelimit-reset")
        if reset is not None:
            try:
                reset_val = float(reset)
                # Some APIs return epoch seconds, others return seconds-until-reset
                if reset_val < 1_000_000_000:
                    # Seconds-until-reset
                    self.reset_at = time.time() + reset_val
                else:
                    # Epoch timestamp
                    self.reset_at = reset_val
            except (ValueError, TypeError):
                pass

        retry = lower.get("retry-after")
        if retry is not None and self.remaining is not None and self.remaining <= 0:
            try:
                self.reset_at = time.time() + float(retry)
            except (ValueError, TypeError):
                pass

    def update_from_429(self, headers: dict) -> None:
        """Handle a 429 response specifically."""
        self.remaining = 0
        self.update_from_headers(headers)
        # Fallback: if no reset info, assume 60s window
        if self.reset_at <= time.time():
            self.reset_at = time.time() + self.window_seconds

    async def wait_if_needed(self) -> float:
        """If budget is exhausted, sleep until reset. Returns wait duration."""
        if not self.is_exhausted:
            self.last_wait_seconds = 0.0
            return 0.0

        wait = self.wait_time
        if wait > 0:
            log.warning(
                "⏳ %s rate limit exhausted — waiting %.1fs for budget reset",
                self.provider,
                wait,
            )
            self._waiting = True
            self.last_wait_seconds = wait
            await asyncio.sleep(wait)
            self._waiting = False
            # Reset budget after wait
            self.remaining = self.default_rpm
            self.reset_at = time.time() + self.window_seconds
            log.info("✓ %s rate limit budget restored", self.provider)

        return wait

    def consume(self) -> None:
        """Decrement the budget by one request."""
        if self.remaining is not None:
            self.remaining = max(0, self.remaining - 1)
        if self.remaining is not None and self.remaining <= 0 and self.reset_at <= time.time():
            self.reset_at = time.time() + self.window_seconds

    def get_status(self) -> dict:
        """Return a status dict for the provider (for UI/SSE)."""
        return {
            "provider": self.provider,
            "remaining": self.remaining,
            "reset_in": max(0, round(self.reset_at - time.time(), 1)) if self.reset_at > time.time() else 0,
            "exhausted": self.is_exhausted,
            "waiting": self._waiting,
            "last_wait": round(self.last_wait_seconds, 1),
        }


# ── Per-provider singleton instances ──────────────────────────────────────────

trackers: dict[str, RateLimitTracker] = {
    "virustotal": RateLimitTracker(provider="VirusTotal", default_rpm=4, window_seconds=60),
    "abuseipdb": RateLimitTracker(provider="AbuseIPDB", default_rpm=15, window_seconds=60),
    "greynoise": RateLimitTracker(provider="GreyNoise", default_rpm=30, window_seconds=60),
    "shodan": RateLimitTracker(provider="Shodan", default_rpm=60, window_seconds=60),
    "alienvault": RateLimitTracker(provider="AlienVault", default_rpm=30, window_seconds=60),
}


def get_tracker(name: str) -> RateLimitTracker:
    """Get the tracker for a provider by name."""
    return trackers[name]


def get_all_status() -> list[dict]:
    """Return budget status for all providers."""
    return [t.get_status() for t in trackers.values()]
