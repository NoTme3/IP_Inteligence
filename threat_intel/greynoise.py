"""GreyNoise Community API — Internet noise & RIOT classification.

GreyNoise helps determine whether an IP is:
  - Background noise (mass scanners, benign crawlers)
  - Part of RIOT (Rule It Out) — known-good services like Google, Microsoft, etc.
  - Truly targeted / malicious traffic

Community API: Free, no key required for basic lookups.
Full API: Requires a key for richer context.
"""

from __future__ import annotations

import httpx

from models import GreyNoiseResult
from utils.logger import get_logger

log = get_logger("greynoise")

_COMMUNITY_URL = "https://api.greynoise.io/v3/community"
_FULL_URL = "https://api.greynoise.io/v2/noise/context"


async def query_greynoise(
    ip: str,
    client: httpx.AsyncClient,
    *,
    api_key: str = "",
) -> GreyNoiseResult:
    """Query GreyNoise for an IP address.

    Uses the full API if a key is provided, otherwise falls back
    to the free Community API.

    Parameters
    ----------
    ip:
        The IP address to look up.
    client:
        A shared ``httpx.AsyncClient`` instance.
    api_key:
        Optional GreyNoise API key (full API). Falls back to Community.

    Returns
    -------
    GreyNoiseResult
        Classification, noise status, and RIOT data.
    """
    try:
        if api_key:
            return await _query_full(ip, client, api_key)
        else:
            return await _query_community(ip, client)

    except httpx.HTTPStatusError as exc:
        log.error(
            "GreyNoise HTTP %d for %s: %s",
            exc.response.status_code,
            ip,
            exc.response.text[:200],
        )
        return GreyNoiseResult(available=False)

    except Exception as exc:
        log.error("GreyNoise error for %s: %s", ip, exc)
        return GreyNoiseResult(available=False)


async def _query_community(
    ip: str, client: httpx.AsyncClient
) -> GreyNoiseResult:
    """Use the free Community API (no key required)."""
    url = f"{_COMMUNITY_URL}/{ip}"
    headers = {"accept": "application/json"}

    log.debug("Querying GreyNoise Community for %s", ip)
    resp = await client.get(url, headers=headers)

    if resp.status_code == 404:
        # IP not found in GreyNoise database — that's okay
        log.debug("GreyNoise: %s not found in database", ip)
        return GreyNoiseResult(
            seen=False,
            classification="unknown",
            available=True,
        )

    resp.raise_for_status()
    data = resp.json()

    result = GreyNoiseResult(
        seen=data.get("noise", False),
        classification=data.get("classification", "unknown"),
        name=data.get("name", ""),
        riot=data.get("riot", False),
        message=data.get("message", ""),
        available=True,
    )

    log.info(
        "GreyNoise Community [%s]: classification=%s noise=%s riot=%s",
        ip,
        result.classification,
        result.seen,
        result.riot,
    )
    return result


async def _query_full(
    ip: str, client: httpx.AsyncClient, api_key: str
) -> GreyNoiseResult:
    """Use the full GreyNoise API (requires key)."""
    url = f"{_FULL_URL}/{ip}"
    headers = {
        "accept": "application/json",
        "key": api_key,
    }

    log.debug("Querying GreyNoise Full API for %s", ip)
    resp = await client.get(url, headers=headers)

    if resp.status_code == 404:
        log.debug("GreyNoise: %s not found in database", ip)
        return GreyNoiseResult(
            seen=False,
            classification="unknown",
            available=True,
        )

    resp.raise_for_status()
    data = resp.json()

    result = GreyNoiseResult(
        seen=data.get("seen", False),
        classification=data.get("classification", "unknown"),
        name=data.get("actor", "") or data.get("name", ""),
        riot=data.get("riot", False),
        message=data.get("message", ""),
        last_seen=data.get("last_seen"),
        tags=data.get("tags", []),
        cve=data.get("cve", []),
        category=data.get("metadata", {}).get("category", ""),
        available=True,
    )

    log.info(
        "GreyNoise Full [%s]: classification=%s seen=%s riot=%s tags=%d",
        ip,
        result.classification,
        result.seen,
        result.riot,
        len(result.tags),
    )
    return result
