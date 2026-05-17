"""RDAP lookup for IP ownership and network information via ipwhois."""

from __future__ import annotations

import asyncio

from ipwhois import IPWhois
from ipwhois.exceptions import (
    ASNRegistryError,
    HTTPLookupError,
    HTTPRateLimitError,
    IPDefinedError,
    WhoisLookupError,
)

from ip_intel.models import OwnershipInfo
from ip_intel.utils.logger import get_logger

log = get_logger("rdap")


def _sync_rdap_lookup(ip: str) -> OwnershipInfo:
    """Perform a synchronous RDAP lookup (runs in a thread)."""
    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap(depth=1)

        # Extract network block
        network = result.get("network", {}) or {}

        return OwnershipInfo(
            asn=result.get("asn"),
            asn_description=result.get("asn_description"),
            org=(
                network.get("name")
                or result.get("asn_description")
            ),
            cidr=result.get("asn_cidr"),
            country=result.get("asn_country_code"),
            rir=result.get("asn_registry"),
            netblock_start=network.get("start_address"),
            netblock_end=network.get("end_address"),
        )

    except IPDefinedError:
        log.warning("IP %s is a private/reserved address", ip)
        return OwnershipInfo()

    except HTTPRateLimitError:
        log.warning("RDAP rate-limited for %s — returning partial data", ip)
        return OwnershipInfo()

    except (ASNRegistryError, HTTPLookupError, WhoisLookupError) as exc:
        log.warning("RDAP lookup failed for %s: %s", ip, exc)
        return OwnershipInfo()

    except Exception as exc:
        log.error("Unexpected RDAP error for %s: %s", ip, exc)
        return OwnershipInfo()


async def lookup_rdap(ip: str) -> OwnershipInfo:
    """Async wrapper — runs the synchronous ipwhois call in a thread pool.

    Parameters
    ----------
    ip:
        The IP address to look up.

    Returns
    -------
    OwnershipInfo
        Parsed network ownership data.
    """
    log.debug("RDAP lookup: %s", ip)
    info = await asyncio.to_thread(_sync_rdap_lookup, ip)
    log.debug(
        "RDAP result for %s: ASN=%s  Org=%s  Country=%s",
        ip,
        info.asn,
        info.org,
        info.country,
    )
    return info
