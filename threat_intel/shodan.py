"""Shodan — passive internet intelligence (open ports, services, banners).

Supports two modes:
1. **Full Shodan API** (requires API key) — detailed banners, service versions
2. **InternetDB API** (free, no key) — basic open ports, tags, hostnames, vulns
"""

from __future__ import annotations

import asyncio
from typing import Optional

import httpx

from config import settings
from models import ShodanResult, ShodanService
from utils.http_client import rate_limited_get, shodan_limiter
from utils.logger import get_logger
from utils.rate_tracker import get_tracker

log = get_logger("shodan")

_SHODAN_API_URL = "https://api.shodan.io/shodan/host"
_INTERNETDB_URL = "https://internetdb.shodan.io"

# Ports commonly associated with risky/suspicious exposure
_SUSPICIOUS_PORTS = {
    23,     # Telnet
    445,    # SMB
    1433,   # MSSQL
    1521,   # Oracle DB
    3306,   # MySQL
    3389,   # RDP
    5432,   # PostgreSQL
    5900,   # VNC
    6379,   # Redis
    11211,  # Memcached
    27017,  # MongoDB
}


async def _query_shodan_api(
    ip: str,
    client: httpx.AsyncClient,
    *,
    api_key: str = "",
) -> Optional[ShodanResult]:
    """Query the full Shodan API (requires API key)."""
    key = api_key or settings.shodan_api_key
    url = f"{_SHODAN_API_URL}/{ip}"
    params = {"key": key}

    try:
        log.debug("Querying Shodan API for %s", ip)
        response = await rate_limited_get(
            client, url, shodan_limiter, params=params,
            tracker=get_tracker("shodan"),
        )
        data = response.json()

        services: list[ShodanService] = []
        for banner in data.get("data", []):
            services.append(ShodanService(
                port=banner.get("port", 0),
                protocol=banner.get("transport", "tcp"),
                service=banner.get("product") or banner.get("_shodan", {}).get("module", "unknown"),
                version=banner.get("version"),
                banner=(banner.get("data", "")[:500] or None),
                cpe=banner.get("cpe", []) if isinstance(banner.get("cpe"), list) else [],
            ))

        open_ports = sorted(data.get("ports", []))

        result = ShodanResult(
            open_ports=open_ports,
            services=services,
            os=data.get("os"),
            hostnames=data.get("hostnames", []),
            tags=data.get("tags", []),
            vulns=list(data.get("vulns", {}).keys()) if isinstance(data.get("vulns"), dict) else data.get("vulns", []),
            org=data.get("org"),
            isp=data.get("isp"),
            last_update=data.get("last_update"),
            available=True,
            source="shodan_api",
        )

        log.info(
            "Shodan API [%s]: %d port(s), %d service(s), %d vuln(s)",
            ip, len(open_ports), len(services), len(result.vulns),
        )
        return result

    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            log.info("Shodan API: no data for %s", ip)
            return ShodanResult(available=True, source="shodan_api")
        log.error(
            "Shodan API HTTP %d for %s: %s",
            exc.response.status_code, ip, exc.response.text[:200],
        )
        return None

    except Exception as exc:
        log.error("Shodan API error for %s: %s", ip, exc)
        return None


async def _query_internetdb(
    ip: str,
    client: httpx.AsyncClient,
) -> ShodanResult:
    """Query the free InternetDB API (no key required)."""
    url = f"{_INTERNETDB_URL}/{ip}"

    try:
        log.debug("Querying InternetDB for %s", ip)
        response = await client.get(url, timeout=10)

        if response.status_code == 404:
            log.info("InternetDB: no data for %s", ip)
            return ShodanResult(available=True, source="internetdb")

        response.raise_for_status()
        data = response.json()

        open_ports = sorted(data.get("ports", []))
        hostnames = data.get("hostnames", [])
        tags = data.get("tags", [])
        vulns = data.get("vulns", [])
        cpes = data.get("cpes", [])

        # Build basic services from ports (InternetDB doesn't provide banners)
        services: list[ShodanService] = []
        for port in open_ports:
            services.append(ShodanService(
                port=port,
                protocol="tcp",
                service=_guess_service_name(port),
            ))

        result = ShodanResult(
            open_ports=open_ports,
            services=services,
            hostnames=hostnames,
            tags=tags,
            vulns=vulns,
            available=True,
            source="internetdb",
        )

        log.info(
            "InternetDB [%s]: %d port(s), %d vuln(s), tags=%s",
            ip, len(open_ports), len(vulns), tags,
        )
        return result

    except Exception as exc:
        log.warning("InternetDB error for %s: %s", ip, exc)
        return ShodanResult(available=False, source="internetdb")


async def query_shodan(
    ip: str,
    client: httpx.AsyncClient,
    *,
    api_key: str = "",
) -> ShodanResult:
    """Query Shodan for open ports and services.

    Uses the full Shodan API if an API key is configured, otherwise
    falls back to the free InternetDB API.

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
    ShodanResult
        Ports, services, banners, vulnerabilities, and tags.
    """
    key = api_key or settings.shodan_api_key
    # Try full API first if key is available
    if key:
        result = await _query_shodan_api(ip, client, api_key=key)
        if result is not None:
            return result
        log.warning("Shodan API failed for %s, falling back to InternetDB", ip)

    # Fallback to free InternetDB
    return await _query_internetdb(ip, client)


def _guess_service_name(port: int) -> str:
    """Best-effort service name guess from port number."""
    _COMMON = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC",
        139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        465: "SMTPS", 587: "Submission", 993: "IMAPS", 995: "POP3S",
        1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 3306: "MySQL",
        3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 5901: "VNC",
        6379: "Redis", 6443: "Kubernetes", 8080: "HTTP-Proxy",
        8443: "HTTPS-Alt", 8888: "HTTP-Alt", 9200: "Elasticsearch",
        9300: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
    }
    return _COMMON.get(port, f"port-{port}")
