"""OFAC / OpenSanctions cross-check — flags sanctioned entities.

Downloads the OpenSanctions consolidated dataset and fuzzy-matches
registrant org / ASN owner names against SDN entity names.
No API key required (CC-BY 4.0 data).
"""

from __future__ import annotations

import asyncio
import time
from difflib import SequenceMatcher
from typing import Optional

import httpx

from models import SanctionsResult
from utils.logger import get_logger

log = get_logger("sanctions")

# ── In-memory sanctions cache ────────────────────────────────────────────────

_SANCTIONS_URL = "https://data.opensanctions.org/datasets/latest/default/names.txt"
_cache: list[str] = []
_cache_loaded_at: float = 0.0
_CACHE_TTL = 86400  # 24 hours
_loading_lock = asyncio.Lock()


async def _load_sanctions_list() -> list[str]:
    """Download and cache the OpenSanctions names list."""
    global _cache, _cache_loaded_at

    async with _loading_lock:
        # Double-check after acquiring lock
        if _cache and (time.time() - _cache_loaded_at) < _CACHE_TTL:
            return _cache

        log.info("Downloading OpenSanctions names list...")
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(_SANCTIONS_URL)
                resp.raise_for_status()

                names = []
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        names.append(line.lower())

                _cache = names
                _cache_loaded_at = time.time()
                log.info(
                    "Loaded %d sanctioned entity names (%.1f KB)",
                    len(names),
                    len(resp.text) / 1024,
                )
                return _cache

        except Exception as exc:
            log.warning("Failed to load sanctions list: %s", exc)
            return _cache  # Return stale cache if available


def _best_match(query: str, names: list[str], threshold: float = 0.82) -> tuple[str, float]:
    """Find the best fuzzy match for *query* in the sanctions names list.

    Uses SequenceMatcher for O(n) comparison — acceptable for ~200k names
    when called infrequently (once per IP, not per request).
    """
    query_lower = query.lower().strip()
    if not query_lower or len(query_lower) < 3:
        return "", 0.0

    best_name = ""
    best_score = 0.0

    # If the query is very short (e.g. acronyms like "GOGL", "AS123"), 
    # we should require an exact match rather than fuzzy or substring.
    if len(query_lower) <= 5:
        if query_lower in names:
            return query_lower, 1.0
        return "", 0.0

    # Fuzzy match (slower, only on subset)
    for name in names:
        # Skip names that are too short or too different in length
        if abs(len(name) - len(query_lower)) > max(len(query_lower) * 0.4, 5):
            continue

        score = SequenceMatcher(None, query_lower, name).ratio()
        if score > best_score:
            best_score = score
            best_name = name

    if best_score >= threshold:
        return best_name, best_score
    return "", 0.0


async def check_sanctions(
    org_name: Optional[str] = None,
    asn_owner: Optional[str] = None,
) -> SanctionsResult:
    """Check organization names against the OFAC/OpenSanctions list.

    Parameters
    ----------
    org_name:
        Network registrant organization name (from RDAP).
    asn_owner:
        ASN description / owner name.

    Returns
    -------
    SanctionsResult
        Match result with entity name and confidence score.
    """
    names = await _load_sanctions_list()
    if not names:
        log.debug("Sanctions list empty — skipping check")
        return SanctionsResult()

    # Check both org name and ASN owner
    candidates = []
    if org_name and org_name.lower() not in ("unknown", "n/a", ""):
        candidates.append(org_name)
    if asn_owner and asn_owner.lower() not in ("unknown", "n/a", ""):
        candidates.append(asn_owner)

    if not candidates:
        return SanctionsResult()

    best_entity = ""
    best_score = 0.0

    for candidate in candidates:
        entity, score = await asyncio.to_thread(_best_match, candidate, names)
        if score > best_score:
            best_entity = entity
            best_score = score

    if best_score >= 0.82:
        log.warning(
            "⚠️  SANCTIONS MATCH: '%s' → '%s' (score=%.2f)",
            candidates[0],
            best_entity,
            best_score,
        )
        return SanctionsResult(
            is_sanctioned=True,
            matched_entity=best_entity.title(),
            match_score=round(best_score, 3),
            sanctions_program="OFAC SDN / OpenSanctions",
        )

    return SanctionsResult()
