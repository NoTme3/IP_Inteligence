"""Pipeline orchestrator — coordinates enrichment, scoring, and storage."""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from typing import Optional

from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from config import Settings, settings
from enrichment.dns import resolve_ptr
from enrichment.rdap import lookup_rdap
from models import IPInput, IPIntelligenceReport
from scoring.engine import compute_risk_score
from storage.database import Database
from threat_intel.abuseipdb import query_abuseipdb
from threat_intel.shodan import query_shodan
from threat_intel.virustotal import query_virustotal
from utils.http_client import create_client
from utils.logger import get_logger

log = get_logger("pipeline")


async def _enrich_single(
    ip_input: IPInput,
    client,
    semaphore: asyncio.Semaphore,
) -> IPIntelligenceReport:
    """Run the full enrichment pipeline for a single IP address."""
    async with semaphore:
        start = time.monotonic()
        report = IPIntelligenceReport(
            ip=ip_input.ip,
            ip_version=ip_input.ip_version,
            timestamp=ip_input.timestamp,
        )

        # Run all enrichment tasks concurrently
        rdap_task = lookup_rdap(ip_input.ip)
        dns_task = resolve_ptr(ip_input.ip)
        vt_task = query_virustotal(ip_input.ip, client)
        abuse_task = query_abuseipdb(ip_input.ip, client)
        shodan_task = query_shodan(ip_input.ip, client)

        results = await asyncio.gather(
            rdap_task, dns_task, vt_task, abuse_task, shodan_task,
            return_exceptions=True,
        )

        # Assign results (handle exceptions gracefully)
        if isinstance(results[0], Exception):
            report.errors.append(f"RDAP: {results[0]}")
            log.error("RDAP failed for %s: %s", ip_input.ip, results[0])
        else:
            report.ownership = results[0]

        if isinstance(results[1], Exception):
            report.errors.append(f"DNS: {results[1]}")
            log.error("DNS failed for %s: %s", ip_input.ip, results[1])
        else:
            report.dns = results[1]

        if isinstance(results[2], Exception):
            report.errors.append(f"VirusTotal: {results[2]}")
            log.error("VT failed for %s: %s", ip_input.ip, results[2])
        else:
            report.virustotal = results[2]

        if isinstance(results[3], Exception):
            report.errors.append(f"AbuseIPDB: {results[3]}")
            log.error("AbuseIPDB failed for %s: %s", ip_input.ip, results[3])
        else:
            report.abuseipdb = results[3]

        if isinstance(results[4], Exception):
            report.errors.append(f"Shodan: {results[4]}")
            log.error("Shodan failed for %s: %s", ip_input.ip, results[4])
        else:
            report.shodan = results[4]

        # Compute risk score
        report.risk = compute_risk_score(report)
        report.query_duration_s = round(time.monotonic() - start, 2)

        return report


async def run_pipeline(
    ips: list[IPInput],
    *,
    store: bool = True,
    cfg: Optional[Settings] = None,
) -> list[IPIntelligenceReport]:
    """Run the full intelligence pipeline for a list of IPs.

    Parameters
    ----------
    ips:
        Validated IP inputs to process.
    store:
        Whether to persist results to the database.
    cfg:
        Optional settings override (uses singleton by default).

    Returns
    -------
    list[IPIntelligenceReport]
        Completed intelligence reports.
    """
    cfg = cfg or settings

    if not ips:
        log.warning("No IPs to process")
        return []

    log.info("Starting pipeline for %d IP(s)", len(ips))

    # Warn if no API keys
    if not cfg.has_virustotal():
        log.warning(
            "VIRUSTOTAL_API_KEY not set — VirusTotal lookups will be skipped"
        )
    if not cfg.has_abuseipdb():
        log.warning(
            "ABUSEIPDB_API_KEY not set — AbuseIPDB lookups will be skipped"
        )

    semaphore = asyncio.Semaphore(cfg.max_concurrency)
    reports: list[IPIntelligenceReport] = []

    async with create_client() as client:
        db = Database()
        try:
            await db.connect()

            # Check cache first
            tasks = []
            new_reports = []
            
            for ip_input in ips:
                cached = await db.get_by_ip(ip_input.ip)
                if cached and cached.get("raw_data"):
                    updated_at_str = cached.get("updated_at")
                    if updated_at_str:
                        try:
                            updated_at = datetime.fromisoformat(updated_at_str)
                            age = (datetime.now(timezone.utc) - updated_at).total_seconds()
                            if age < cfg.cache_ttl:
                                try:
                                    report = IPIntelligenceReport.model_validate_json(cached["raw_data"])
                                    reports.append(report)
                                    log.debug("Loaded %s from cache", ip_input.ip)
                                    continue
                                except Exception as e:
                                    log.warning("Failed to parse cached data for %s: %s", ip_input.ip, e)
                        except ValueError:
                            pass
                
                # If not cached or stale, we need to analyze it
                tasks.append(_enrich_single(ip_input, client, semaphore))

            if reports:
                log.info("Loaded %d IP(s) from cache", len(reports))

            if tasks:
                log.info("Fetching intelligence for %d IP(s) from APIs...", len(tasks))
                # Rich progress bar
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[bold blue]{task.description}"),
                    BarColumn(bar_width=40),
                    MofNCompleteColumn(),
                    TimeElapsedColumn(),
                ) as progress:
                    task_id = progress.add_task("Analyzing IPs", total=len(tasks))

                    try:
                        # Process as they complete
                        for coro in asyncio.as_completed(tasks):
                            report = await coro
                            reports.append(report)
                            new_reports.append(report)
                            progress.advance(task_id)
                            log.info(
                                "✓ %s → score=%d (%s) [%.1fs]",
                                report.ip,
                                report.risk.score,
                                report.risk.classification.value,
                                report.query_duration_s,
                            )
                            if store:
                                await db.upsert_report(report)
                            
                    except (KeyboardInterrupt, asyncio.CancelledError):
                        log.warning("⚠️  Analysis interrupted by user! Partial progress has been saved to the database.")
                        # Allow remaining tasks to be cancelled cleanly
                        for t in tasks:
                            if hasattr(t, "cancel"):
                                t.cancel()

        finally:
            await db.close()

    # Sort by score descending
    reports.sort(key=lambda r: r.risk.score, reverse=True)

    return reports


# ── Web-friendly enrichment (no Rich, no DB) ─────────────────────────────────


async def enrich_single_web(
    ip: str,
    client,
    *,
    vt_key: str = "",
    abuse_key: str = "",
    shodan_key: str = "",
) -> IPIntelligenceReport:
    """Lightweight enrichment for web/serverless use — no DB, no progress bar.

    API keys are passed per-request (from the user's browser) and never stored.

    Parameters
    ----------
    ip:
        The IP address to enrich.
    client:
        A shared ``httpx.AsyncClient``.
    vt_key:
        User-provided VirusTotal API key (optional).
    abuse_key:
        User-provided AbuseIPDB API key (optional).
    shodan_key:
        User-provided Shodan API key (optional).

    Returns
    -------
    IPIntelligenceReport
        The enriched intelligence report.
    """
    import ipaddress

    start = time.monotonic()

    try:
        version = ipaddress.ip_address(ip).version
    except ValueError:
        version = 4

    report = IPIntelligenceReport(ip=ip, ip_version=version)

    rdap_task = lookup_rdap(ip)
    dns_task = resolve_ptr(ip)
    vt_task = query_virustotal(ip, client, api_key=vt_key)
    abuse_task = query_abuseipdb(ip, client, api_key=abuse_key)
    shodan_task = query_shodan(ip, client, api_key=shodan_key)

    results = await asyncio.gather(
        rdap_task, dns_task, vt_task, abuse_task, shodan_task,
        return_exceptions=True,
    )

    if not isinstance(results[0], Exception):
        report.ownership = results[0]
    else:
        report.errors.append(f"RDAP: {results[0]}")

    if not isinstance(results[1], Exception):
        report.dns = results[1]
    else:
        report.errors.append(f"DNS: {results[1]}")

    if not isinstance(results[2], Exception):
        report.virustotal = results[2]
    else:
        report.errors.append(f"VirusTotal: {results[2]}")

    if not isinstance(results[3], Exception):
        report.abuseipdb = results[3]
    else:
        report.errors.append(f"AbuseIPDB: {results[3]}")

    if not isinstance(results[4], Exception):
        report.shodan = results[4]
    else:
        report.errors.append(f"Shodan: {results[4]}")

    report.risk = compute_risk_score(report)
    report.query_duration_s = round(time.monotonic() - start, 2)

    return report

