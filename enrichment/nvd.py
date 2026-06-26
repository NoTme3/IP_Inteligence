"""CVE detail enrichment via the NVD (National Vulnerability Database) API.

Queries the free NVD 2.0 API to enrich bare CVE IDs (from Shodan/GreyNoise)
with CVSS scores, severity ratings, and descriptions.
No API key required. Rate-limited to 5 req/30s.
"""

from __future__ import annotations

import asyncio
from typing import Optional

import httpx
from aiolimiter import AsyncLimiter

from models import CVEDetail
from utils.logger import get_logger

log = get_logger("nvd")

# NVD free tier: 5 requests per 30 seconds (without API key)
_nvd_limiter = AsyncLimiter(5, 30)

# In-memory cache (CVE data rarely changes)
_cve_cache: dict[str, CVEDetail] = {}

_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


async def _fetch_cve(cve_id: str, client: httpx.AsyncClient) -> Optional[CVEDetail]:
    """Fetch a single CVE from NVD and parse the response."""
    if cve_id in _cve_cache:
        return _cve_cache[cve_id]

    async with _nvd_limiter:
        try:
            resp = await client.get(
                _NVD_BASE,
                params={"cveId": cve_id},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return None

            cve_data = vulns[0].get("cve", {})

            # Extract CVSS v3.1 score
            cvss_score = 0.0
            severity = ""
            metrics = cve_data.get("metrics", {})

            # Try CVSS v3.1 first, then v3.0, then v2.0
            for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(version_key, [])
                if metric_list:
                    cvss_data = metric_list[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", 0.0)
                    severity = cvss_data.get("baseSeverity", "").upper()
                    break

            # If no severity from CVSS, derive from score
            if not severity and cvss_score > 0:
                if cvss_score >= 9.0:
                    severity = "CRITICAL"
                elif cvss_score >= 7.0:
                    severity = "HIGH"
                elif cvss_score >= 4.0:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"

            # Extract description (prefer English)
            description = ""
            for desc in cve_data.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            # Truncate long descriptions
            if len(description) > 300:
                description = description[:297] + "..."

            # Extract affected products from CPE matches
            affected = []
            configs = cve_data.get("configurations", [])
            for config in configs[:3]:  # Limit
                for node in config.get("nodes", [])[:3]:
                    for match in node.get("cpeMatch", [])[:5]:
                        criteria = match.get("criteria", "")
                        # Parse CPE URI: cpe:2.3:a:vendor:product:version:...
                        parts = criteria.split(":")
                        if len(parts) >= 5:
                            vendor = parts[3]
                            product = parts[4]
                            version = parts[5] if len(parts) > 5 and parts[5] != "*" else ""
                            label = f"{vendor}/{product}"
                            if version:
                                label += f" {version}"
                            if label not in affected:
                                affected.append(label)

            detail = CVEDetail(
                cve_id=cve_id,
                cvss_score=cvss_score,
                severity=severity,
                description=description,
                affected_products=affected[:10],
            )

            _cve_cache[cve_id] = detail
            return detail

        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                log.debug("CVE %s not found in NVD", cve_id)
            else:
                log.warning("NVD API error for %s: %s", cve_id, exc)
            return None
        except Exception as exc:
            log.warning("NVD fetch failed for %s: %s", cve_id, exc)
            return None


async def enrich_cves(
    cve_ids: list[str],
    client: httpx.AsyncClient,
    max_cves: int = 10,
) -> list[CVEDetail]:
    """Enrich a list of CVE IDs with details from NVD.

    Parameters
    ----------
    cve_ids:
        List of CVE ID strings (e.g., ["CVE-2023-44487", "CVE-2021-44228"]).
    client:
        Shared httpx async client.
    max_cves:
        Maximum number of CVEs to enrich (to limit API calls).

    Returns
    -------
    list[CVEDetail]
        Enriched CVE details, sorted by CVSS score descending.
    """
    if not cve_ids:
        return []

    # Deduplicate and limit
    unique_ids = list(dict.fromkeys(cve_ids))[:max_cves]

    log.debug("Enriching %d CVEs via NVD", len(unique_ids))

    tasks = [_fetch_cve(cve_id, client) for cve_id in unique_ids]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    details = []
    for result in results:
        if isinstance(result, CVEDetail):
            details.append(result)
        elif isinstance(result, Exception):
            log.debug("CVE enrichment error: %s", result)

    # Sort by CVSS score descending
    details.sort(key=lambda d: d.cvss_score, reverse=True)

    log.info(
        "Enriched %d/%d CVEs (highest: %s %.1f)",
        len(details),
        len(unique_ids),
        details[0].cve_id if details else "N/A",
        details[0].cvss_score if details else 0,
    )

    return details
