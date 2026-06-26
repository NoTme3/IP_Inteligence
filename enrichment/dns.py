"""DNS resolution — PTR lookups and full forward DNS record enumeration.

Performs reverse DNS (PTR), forward-confirmed reverse DNS (FCrDNS),
and full record resolution (A, AAAA, MX, NS, TXT) using dnspython.
"""

from __future__ import annotations

import asyncio
import socket
from typing import Optional

import dns.resolver
import dns.reversename
import dns.exception

from models import DNSInfo
from utils.logger import get_logger

log = get_logger("dns")


def _sync_ptr_lookup(ip: str) -> DNSInfo:
    """Perform a synchronous reverse DNS lookup (runs in a thread)."""
    try:
        hostname, aliases, _ = socket.gethostbyaddr(ip)
        return DNSInfo(
            ptr=hostname,
            aliases=list(aliases) if aliases else [],
        )
    except (socket.herror, socket.gaierror):
        log.debug("No PTR record for %s", ip)
        return DNSInfo()
    except socket.timeout:
        log.warning("PTR lookup timed out for %s", ip)
        return DNSInfo()
    except Exception as exc:
        log.warning("PTR lookup error for %s: %s", ip, exc)
        return DNSInfo()


def _resolve_records(domain: str, rdtype: str) -> list[str]:
    """Resolve DNS records of a given type for a domain."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 5
        answers = resolver.resolve(domain, rdtype)
        results = []
        for rdata in answers:
            if rdtype == "MX":
                results.append(f"{rdata.preference} {rdata.exchange}")
            else:
                results.append(str(rdata))
        return results[:20]  # Cap at 20 records
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except dns.exception.DNSException:
        return []
    except Exception:
        return []


def _check_fcrdns(ip: str, ptr_hostname: str) -> bool:
    """Check Forward-Confirmed Reverse DNS.

    FCrDNS passes if the PTR hostname resolves back to the original IP.
    This is a strong indicator that the IP legitimately belongs to the domain.
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 5

        # Try A records first
        try:
            answers = resolver.resolve(ptr_hostname, "A")
            for rdata in answers:
                if str(rdata) == ip:
                    return True
        except dns.exception.DNSException:
            pass

        # Try AAAA records
        try:
            answers = resolver.resolve(ptr_hostname, "AAAA")
            for rdata in answers:
                if str(rdata) == ip:
                    return True
        except dns.exception.DNSException:
            pass

        return False
    except Exception:
        return False


def _full_dns_lookup(ip: str) -> DNSInfo:
    """Perform full DNS resolution: PTR + forward records + FCrDNS."""
    info = _sync_ptr_lookup(ip)

    if not info.ptr:
        return info

    # Extract base domain from PTR for forward lookups
    ptr_domain = info.ptr.rstrip(".")

    # Forward-Confirmed Reverse DNS check
    info.fcrdns_valid = _check_fcrdns(ip, ptr_domain)

    if info.fcrdns_valid:
        log.debug("FCrDNS PASS for %s ↔ %s", ip, ptr_domain)
    else:
        log.info("FCrDNS FAIL for %s → %s (forward lookup doesn't match)", ip, ptr_domain)

    # Resolve full records for the PTR domain
    info.a_records = _resolve_records(ptr_domain, "A")
    info.aaaa_records = _resolve_records(ptr_domain, "AAAA")
    info.mx_records = _resolve_records(ptr_domain, "MX")
    info.ns_records = _resolve_records(ptr_domain, "NS")
    info.txt_records = _resolve_records(ptr_domain, "TXT")

    record_count = (
        len(info.a_records) + len(info.aaaa_records) +
        len(info.mx_records) + len(info.ns_records) +
        len(info.txt_records)
    )
    log.debug("Full DNS for %s: %d records across 5 types", ptr_domain, record_count)

    return info


async def resolve_ptr(ip: str, timeout: float = 5.0) -> DNSInfo:
    """Resolve the PTR record for *ip* asynchronously.

    Parameters
    ----------
    ip:
        The IP address to resolve.
    timeout:
        Maximum seconds to wait.

    Returns
    -------
    DNSInfo
        The PTR hostname and any aliases, or empty on failure.
    """
    log.debug("PTR lookup: %s", ip)

    # Set the socket-level timeout for the blocking call
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)

    try:
        info = await asyncio.to_thread(_full_dns_lookup, ip)
    finally:
        socket.setdefaulttimeout(old_timeout)

    if info.ptr:
        log.debug("PTR for %s → %s", ip, info.ptr)
    return info
