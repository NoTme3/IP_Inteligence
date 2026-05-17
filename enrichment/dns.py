"""Reverse DNS (PTR) resolution."""

from __future__ import annotations

import asyncio
import socket

from ip_intel.models import DNSInfo
from ip_intel.utils.logger import get_logger

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
        info = await asyncio.to_thread(_sync_ptr_lookup, ip)
    finally:
        socket.setdefaulttimeout(old_timeout)

    if info.ptr:
        log.debug("PTR for %s → %s", ip, info.ptr)
    return info
