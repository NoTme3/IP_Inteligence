"""VirusTotal API v3 — IP address intelligence."""

from __future__ import annotations

import asyncio
import httpx

from config import settings
from models import VirusTotalResult
from utils.http_client import rate_limited_get, vt_limiter
from utils.logger import get_logger

log = get_logger("virustotal")

_BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses"


async def query_virustotal(
    ip: str,
    client: httpx.AsyncClient,
    *,
    api_key: str = "",
) -> VirusTotalResult:
    """Query VirusTotal for an IP address report.

    Parameters
    ----------
    ip:
        The IP address to look up.
    client:
        A shared ``httpx.AsyncClient`` instance.
    api_key:
        Optional API key override (for web UI). Falls back to settings.

    Returns
    -------
    VirusTotalResult
        Parsed detection statistics and reputation data.
    """
    key = api_key or settings.virustotal_api_key
    if not key:
        log.warning("VirusTotal API key not configured — skipping")
        return VirusTotalResult(available=False)

    url = f"{_BASE_URL}/{ip}"
    headers = {
        "x-apikey": key,
        "accept": "application/json",
    }

    try:
        log.debug("Querying VirusTotal for %s", ip)
        
        # We need both the main IP report and the resolutions (historic domains)
        # Using asyncio.gather to run them concurrently against VT
        resolutions_url = f"{_BASE_URL}/{ip}/resolutions?limit=20"
        
        main_task = rate_limited_get(client, url, vt_limiter, headers=headers)
        resolutions_task = rate_limited_get(client, resolutions_url, vt_limiter, headers=headers)
        
        responses = await asyncio.gather(main_task, resolutions_task, return_exceptions=True)
        
        # Handle main report
        if isinstance(responses[0], Exception):
            raise responses[0]
            
        main_resp = responses[0]
        data = main_resp.json()

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        # Extract historic domains if resolution query succeeded
        historic_domains = []
        if not isinstance(responses[1], Exception) and responses[1].status_code == 200:
            res_data = responses[1].json().get("data", [])
            for item in res_data:
                host = item.get("attributes", {}).get("host_name")
                if host and host not in historic_domains:
                    historic_domains.append(host)

        result = VirusTotalResult(
            malicious=stats.get("malicious", 0),
            suspicious=stats.get("suspicious", 0),
            harmless=stats.get("harmless", 0),
            undetected=stats.get("undetected", 0),
            reputation=attrs.get("reputation", 0),
            historic_domains=historic_domains,
            as_owner=attrs.get("as_owner"),
            country=attrs.get("country"),
            available=True,
        )

        log.info(
            "VirusTotal [%s]: malicious=%d  suspicious=%d  reputation=%d",
            ip,
            result.malicious,
            result.suspicious,
            result.reputation,
        )
        return result

    except httpx.HTTPStatusError as exc:
        log.error(
            "VirusTotal HTTP %d for %s: %s",
            exc.response.status_code,
            ip,
            exc.response.text[:200],
        )
        return VirusTotalResult(available=False)

    except Exception as exc:
        log.error("VirusTotal error for %s: %s", ip, exc)
        return VirusTotalResult(available=False)
