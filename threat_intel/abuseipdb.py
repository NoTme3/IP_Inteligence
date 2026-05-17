"""AbuseIPDB API v2 — IP abuse intelligence."""

from __future__ import annotations

import httpx

from ip_intel.config import settings
from ip_intel.models import AbuseIPDBResult
from ip_intel.utils.http_client import abuseipdb_limiter, rate_limited_get
from ip_intel.utils.logger import get_logger

log = get_logger("abuseipdb")

_BASE_URL = "https://api.abuseipdb.com/api/v2/check"


async def query_abuseipdb(
    ip: str,
    client: httpx.AsyncClient,
    *,
    api_key: str = "",
) -> AbuseIPDBResult:
    """Query AbuseIPDB for abuse reports on an IP address.

    Parameters
    ----------
    ip:
        The IP address to check.
    client:
        A shared ``httpx.AsyncClient`` instance.
    api_key:
        Optional API key override (for web UI). Falls back to settings.

    Returns
    -------
    AbuseIPDBResult
        Parsed abuse confidence score, report count, and metadata.
    """
    key = api_key or settings.abuseipdb_api_key
    if not key:
        log.warning("AbuseIPDB API key not configured — skipping")
        return AbuseIPDBResult(available=False)

    headers = {
        "Key": key,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": "90",
        "verbose": "",  # include reports array
    }

    try:
        log.debug("Querying AbuseIPDB for %s", ip)
        response = await rate_limited_get(
            client, _BASE_URL, abuseipdb_limiter,
            headers=headers, params=params,
        )
        body = response.json()
        data = body.get("data", {})

        result = AbuseIPDBResult(
            abuse_confidence_score=data.get("abuseConfidenceScore", 0),
            total_reports=data.get("totalReports", 0),
            is_whitelisted=data.get("isWhitelisted", False) or False,
            isp=data.get("isp"),
            domain=data.get("domain"),
            usage_type=data.get("usageType"),
            country_code=data.get("countryCode"),
            last_reported_at=data.get("lastReportedAt"),
            available=True,
        )

        log.info(
            "AbuseIPDB [%s]: confidence=%d  reports=%d  whitelisted=%s",
            ip,
            result.abuse_confidence_score,
            result.total_reports,
            result.is_whitelisted,
        )
        return result

    except httpx.HTTPStatusError as exc:
        log.error(
            "AbuseIPDB HTTP %d for %s: %s",
            exc.response.status_code,
            ip,
            exc.response.text[:200],
        )
        return AbuseIPDBResult(available=False)

    except Exception as exc:
        log.error("AbuseIPDB error for %s: %s", ip, exc)
        return AbuseIPDBResult(available=False)
