"""Weighted risk scoring engine with explainable signals.

Score range: 0 – 100
Classification:
    0–20   Benign
    21–50  Suspicious
    51–75  Likely Malicious
    76–100 Malicious
"""

from __future__ import annotations

from models import (
    IPIntelligenceReport,
    RiskClassification,
    RiskScore,
    ScoringSignal,
)
from utils.logger import get_logger

log = get_logger("scoring")

# ── Known hosting / cloud ASN descriptions (reduce false positives) ──────────

_CLOUD_PROVIDERS = {
    "google",
    "amazon",
    "aws",
    "microsoft",
    "azure",
    "cloudflare",
    "akamai",
    "fastly",
    "digitalocean",
    "oracle",
    "ovh",
    "linode",
    "vultr",
    "hetzner",
    "gcp",
}

# ── Suspicious hosting keywords (increase score) ─────────────────────────────

_SUSPICIOUS_HOSTING = {
    "bulletproof",
    "offshore",
    "anonymous",
    "vpn",
    "proxy",
    "hosting",
}


def _classify(score: int) -> RiskClassification:
    """Map a numeric score to a risk classification label."""
    if score <= 20:
        return RiskClassification.BENIGN
    if score <= 50:
        return RiskClassification.SUSPICIOUS
    if score <= 75:
        return RiskClassification.LIKELY_MALICIOUS
    return RiskClassification.MALICIOUS


def compute_risk_score(report: IPIntelligenceReport) -> RiskScore:
    """Compute a risk score for *report* using a weighted signal model.

    Each contributing signal is recorded for explainability.

    Returns
    -------
    RiskScore
        Score (0–100), classification label, and list of scoring signals.
    """
    signals: list[ScoringSignal] = []
    raw_score = 0

    vt = report.virustotal
    abuse = report.abuseipdb
    own = report.ownership

    # ── VirusTotal signals ────────────────────────────────────────────────

    if vt.available:
        if vt.malicious > 0:
            weight = min(25, vt.malicious * 3)
            signals.append(ScoringSignal(
                name="VirusTotal Malicious Detections",
                weight=weight,
                reason=f"{vt.malicious} vendor(s) flagged this IP as malicious",
            ))
            raw_score += weight

        if vt.suspicious > 0:
            weight = min(10, vt.suspicious * 2)
            signals.append(ScoringSignal(
                name="VirusTotal Suspicious Detections",
                weight=weight,
                reason=f"{vt.suspicious} vendor(s) flagged this IP as suspicious",
            ))
            raw_score += weight

        if vt.reputation < -5:
            weight = min(10, abs(vt.reputation))
            signals.append(ScoringSignal(
                name="VirusTotal Negative Reputation",
                weight=weight,
                reason=f"Community reputation score: {vt.reputation}",
            ))
            raw_score += weight

    # ── AbuseIPDB signals ─────────────────────────────────────────────────

    if abuse.available:
        if abuse.abuse_confidence_score > 70:
            signals.append(ScoringSignal(
                name="AbuseIPDB High Confidence",
                weight=20,
                reason=f"Abuse confidence score: {abuse.abuse_confidence_score}%",
            ))
            raw_score += 20
        elif abuse.abuse_confidence_score > 40:
            signals.append(ScoringSignal(
                name="AbuseIPDB Moderate Confidence",
                weight=10,
                reason=f"Abuse confidence score: {abuse.abuse_confidence_score}%",
            ))
            raw_score += 10

        if abuse.total_reports > 50:
            signals.append(ScoringSignal(
                name="AbuseIPDB High Report Count",
                weight=10,
                reason=f"{abuse.total_reports} abuse reports in the last 90 days",
            ))
            raw_score += 10
        elif abuse.total_reports > 10:
            signals.append(ScoringSignal(
                name="AbuseIPDB Moderate Report Count",
                weight=5,
                reason=f"{abuse.total_reports} abuse reports in the last 90 days",
            ))
            raw_score += 5

        # Negative weight: whitelisted IPs are less likely malicious
        if abuse.is_whitelisted:
            signals.append(ScoringSignal(
                name="AbuseIPDB Whitelisted",
                weight=-15,
                reason="IP is whitelisted (known benign, e.g. search engine bot)",
            ))
            raw_score -= 15

    # ── ASN / Ownership signals ───────────────────────────────────────────

    if own.asn_description:
        desc_lower = own.asn_description.lower()

        # Known cloud provider → reduce score
        if any(kw in desc_lower for kw in _CLOUD_PROVIDERS):
            signals.append(ScoringSignal(
                name="Known Cloud Provider",
                weight=-5,
                reason=f"ASN belongs to known provider: {own.asn_description}",
            ))
            raw_score -= 5

        # Suspicious hosting → increase score
        if any(kw in desc_lower for kw in _SUSPICIOUS_HOSTING):
            signals.append(ScoringSignal(
                name="Suspicious Hosting Provider",
                weight=5,
                reason=f"ASN description contains suspicious keywords: {own.asn_description}",
            ))
            raw_score += 5

    # No ASN found at all → slight signal
    if not own.asn and not own.org:
        signals.append(ScoringSignal(
            name="Unknown Network",
            weight=5,
            reason="No ASN or organization information found via RDAP",
        ))
        raw_score += 5

    # ── Shodan signals ───────────────────────────────────────────────────

    shodan = report.shodan
    if shodan.available and shodan.open_ports:
        # Suspicious ports exposed
        _SUSPICIOUS_PORTS = {23, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 11211, 27017}
        exposed_suspicious = [p for p in shodan.open_ports if p in _SUSPICIOUS_PORTS]
        if exposed_suspicious:
            port_names = ", ".join(str(p) for p in exposed_suspicious)
            weight = min(10, len(exposed_suspicious) * 3)
            signals.append(ScoringSignal(
                name="Suspicious Exposed Ports",
                weight=weight,
                reason=f"Risky ports exposed: {port_names} (Shodan)",
            ))
            raw_score += weight

        # Known vulnerabilities
        if shodan.vulns:
            weight = min(15, len(shodan.vulns) * 3)
            vuln_sample = ", ".join(shodan.vulns[:5])
            extra = f" (+{len(shodan.vulns) - 5} more)" if len(shodan.vulns) > 5 else ""
            signals.append(ScoringSignal(
                name="Known Vulnerabilities",
                weight=weight,
                reason=f"Shodan reports {len(shodan.vulns)} CVE(s): {vuln_sample}{extra}",
            ))
            raw_score += weight

    # ── No intelligence available ─────────────────────────────────────────

    if not vt.available and not abuse.available and not shodan.available:
        signals.append(ScoringSignal(
            name="No Threat Intel",
            weight=0,
            reason="No threat intelligence APIs were available — score may be unreliable",
        ))

    # ── Finalize ──────────────────────────────────────────────────────────

    final_score = max(0, min(100, raw_score))
    classification = _classify(final_score)

    log.info(
        "Score [%s]: %d (%s) — %d signal(s)",
        report.ip,
        final_score,
        classification.value,
        len(signals),
    )

    return RiskScore(
        score=final_score,
        classification=classification,
        signals=signals,
    )
