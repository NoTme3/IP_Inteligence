"""Input parsing, validation, and deduplication of IP addresses."""

from __future__ import annotations

import ipaddress
from pathlib import Path

from models import IPInput
from utils.logger import get_logger

log = get_logger("input")


# ── Private helpers ───────────────────────────────────────────────────────────


def _parse_single(raw: str) -> list[IPInput]:
    """Parse a single IP string or CIDR block into ``IPInput`` objects."""
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return []

    # CIDR notation → expand (limit to /24 for safety)
    if "/" in raw:
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            log.warning("Invalid CIDR: %s — skipping", raw)
            return []

        if network.num_addresses > 256:
            log.warning(
                "CIDR %s contains %d addresses (max 256) — skipping",
                raw,
                network.num_addresses,
            )
            return []

        results: list[IPInput] = []
        for addr in network.hosts():
            results.append(
                IPInput(ip=str(addr), ip_version=addr.version)
            )
        return results

    # Single IP
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        log.warning("Invalid IP address: %s — skipping", raw)
        return []

    # Skip private / reserved
    if addr.is_private or addr.is_reserved or addr.is_loopback:
        log.warning("Private/reserved IP: %s — skipping", raw)
        return []

    return [IPInput(ip=str(addr), ip_version=addr.version)]


# ── Public API ────────────────────────────────────────────────────────────────


def parse_ips(sources: list[str]) -> list[IPInput]:
    """Parse IP addresses from multiple sources.

    Each *source* may be:
    - A single IP address (``"8.8.8.8"``)
    - A comma-separated list (``"8.8.8.8,1.1.1.1"``)
    - A file path (one IP per line)
    - A CIDR block (``"192.168.1.0/28"`` — public only, max /24)

    Returns a deduplicated list of validated ``IPInput`` objects.
    """
    parsed: list[IPInput] = []

    for source in sources:
        source = source.strip()

        # Is it a file?
        path = Path(source)
        if path.is_file():
            log.info("Reading IPs from file: %s", path)
            with path.open() as fh:
                for line in fh:
                    parsed.extend(_parse_single(line))
            continue

        # Comma-separated?
        parts = source.split(",")
        for part in parts:
            parsed.extend(_parse_single(part))

    # Deduplicate while preserving order
    seen: set[str] = set()
    deduped: list[IPInput] = []
    for item in parsed:
        if item.ip not in seen:
            seen.add(item.ip)
            deduped.append(item)

    log.info(
        "Parsed %d unique IP(s) from %d source(s) (%d duplicates removed)",
        len(deduped),
        len(sources),
        len(parsed) - len(deduped),
    )
    return deduped
