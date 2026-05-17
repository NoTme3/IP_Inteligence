"""Report rendering in JSON, CSV, and HTML formats."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from ip_intel.models import IPIntelligenceReport
from ip_intel.utils.logger import get_logger

log = get_logger("reporting")

_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"


# ── JSON ──────────────────────────────────────────────────────────────────────


def render_json(reports: list[IPIntelligenceReport]) -> str:
    """Render reports as pretty-printed JSON."""
    data = [r.model_dump(mode="json") for r in reports]
    return json.dumps(data, indent=2, default=str)


# ── CSV ───────────────────────────────────────────────────────────────────────


def render_csv(reports: list[IPIntelligenceReport]) -> str:
    """Render reports as a CSV string."""
    if not reports:
        return ""

    buf = io.StringIO()
    writer = csv.writer(buf)

    # Header
    writer.writerow([
        "IP",
        "Version",
        "Score",
        "Classification",
        "ASN",
        "Organization",
        "Country",
        "CIDR",
        "RIR",
        "PTR",
        "VT Malicious",
        "VT Suspicious",
        "VT Reputation",
        "AbuseIPDB Score",
        "AbuseIPDB Reports",
        "Shodan Ports",
        "Shodan Vulns",
        "Signals",
        "Errors",
        "Timestamp",
    ])

    # Rows
    for r in reports:
        signals_str = "; ".join(
            f"{s.name} ({s.weight:+d})" for s in r.risk.signals
        )
        errors_str = "; ".join(r.errors) if r.errors else ""
        writer.writerow([
            r.ip,
            r.ip_version,
            r.risk.score,
            r.risk.classification.value,
            r.ownership.asn or "",
            r.ownership.org or "",
            r.ownership.country or "",
            r.ownership.cidr or "",
            r.ownership.rir or "",
            r.dns.ptr or "",
            r.virustotal.malicious,
            r.virustotal.suspicious,
            r.virustotal.reputation,
            r.abuseipdb.abuse_confidence_score,
            r.abuseipdb.total_reports,
            ",".join(map(str, r.shodan.open_ports)) if r.shodan.available else "",
            ",".join(r.shodan.vulns) if r.shodan.available else "",
            signals_str,
            errors_str,
            r.timestamp.isoformat(),
        ])

    return buf.getvalue()


# ── HTML ──────────────────────────────────────────────────────────────────────


def render_html(reports: list[IPIntelligenceReport]) -> str:
    """Render reports as a styled HTML document using the Jinja2 template."""
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=True,
    )
    template = env.get_template("report.html")

    # Pre-compute summary stats
    total = len(reports)
    benign = sum(1 for r in reports if r.risk.classification.value == "Benign")
    suspicious = sum(1 for r in reports if r.risk.classification.value == "Suspicious")
    likely_mal = sum(1 for r in reports if r.risk.classification.value == "Likely Malicious")
    malicious = sum(1 for r in reports if r.risk.classification.value == "Malicious")

    # Sort by score descending for the report
    sorted_reports = sorted(reports, key=lambda r: r.risk.score, reverse=True)

    return template.render(
        reports=sorted_reports,
        total=total,
        benign=benign,
        suspicious=suspicious,
        likely_malicious=likely_mal,
        malicious=malicious,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )
