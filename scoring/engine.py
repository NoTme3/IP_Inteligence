"""Evidence-aware risk scoring engine with attribution confidence.

Score range: 0 – 100
Classification:
    0–20   Benign
    21–50  Suspicious
    51–75  Likely Malicious
    76–100 Malicious
    N/A    Insufficient Data (when too few feeds responded)

Scoring Model:
    1. Signals are collected into categories: DIRECT_MALICIOUS, CONTEXTUAL, REPUTATION, INFRASTRUCTURE.
    2. Each category has a contribution cap to prevent score inflation.
    3. The final score is computed as a weighted sum of categories, multiplied by an infrastructure modifier.
    4. Corroboration: signals confirmed by multiple sources are boosted; isolated signals are dampened.
    5. Attribution confidence is separate from threat activity score.
"""

import math
from datetime import datetime, timezone

from models import (
    IPIntelligenceReport,
    RiskClassification,
    RiskScore,
    ScoringSignal,
    IntelligenceConflict,
    SignalCategory,
    InfrastructureType,
)
from utils.logger import get_logger

log = get_logger("scoring")

# ── Infrastructure Detection ─────────────────────────────────────────────────

_CLOUD_KEYWORDS = {
    "amazon", "aws", "google", "gcp", "microsoft", "azure",
    "alibaba", "tencent", "oracle", "digitalocean", "linode",
    "vultr", "hetzner", "ovh", "leaseweb",
}

_CDN_KEYWORDS = {
    "cloudflare", "akamai", "fastly", "cdn", "edgecast",
    "limelight", "stackpath", "keycdn", "bunny",
}

_SUSPICIOUS_HOSTING_KEYWORDS = {
    "bulletproof", "offshore", "anonymous",
}

_VPS_KEYWORDS = {
    "vpn", "proxy", "hosting", "vps", "dedicated",
}

# Infrastructure modifier lookup — applied to final score
_INFRA_MODIFIERS = {
    InfrastructureType.SHARED_CLOUD: 0.75,
    InfrastructureType.CDN: 0.65,
    InfrastructureType.RESIDENTIAL: 1.0,
    InfrastructureType.VPS: 1.15,
    InfrastructureType.ENTERPRISE: 0.90,
    InfrastructureType.UNKNOWN: 1.0,
}

# Source confidence weights
SOURCE_CONFIDENCE = {
    "greynoise": 0.95,
    "virustotal": 0.85,
    "abuseipdb": 0.75,
    "shodan": 0.60,
    "otx_curated": 0.55,
    "otx_auto_generated": 0.15,
}

# Category contribution caps
_CATEGORY_CAPS = {
    SignalCategory.DIRECT_MALICIOUS: 100,
    SignalCategory.CONTEXTUAL: 30,
    SignalCategory.REPUTATION: 20,
    SignalCategory.INFRASTRUCTURE: 0,  # infrastructure signals don't add to score
}


# ── Helpers ───────────────────────────────────────────────────────────────────


def _detect_infrastructure_type(report: IPIntelligenceReport) -> InfrastructureType:
    """Classify the infrastructure type from ASN, PTR, and GreyNoise data."""
    own = report.ownership
    gn = report.greynoise
    desc = (own.asn_description or "").lower()
    org = (own.org or "").lower()
    ptr = (report.dns.ptr or "").lower()
    combined = f"{desc} {org} {ptr}"

    # GreyNoise RIOT is the strongest signal for known-good enterprise infra
    if gn.available and gn.riot:
        return InfrastructureType.ENTERPRISE

    if any(kw in combined for kw in _CDN_KEYWORDS):
        return InfrastructureType.CDN
    if any(kw in combined for kw in _CLOUD_KEYWORDS):
        return InfrastructureType.SHARED_CLOUD
    if any(kw in combined for kw in _SUSPICIOUS_HOSTING_KEYWORDS):
        return InfrastructureType.VPS
    if any(kw in combined for kw in _VPS_KEYWORDS):
        return InfrastructureType.VPS

    # Residential heuristic: common ISP patterns in PTR
    residential_hints = {"comcast", "charter", "cox", "att.net", "verizon",
                         "spectrum", "dsl", "cable", "broadband", "residential",
                         "dynamic", "pool", "dhcp"}
    if any(hint in combined for hint in residential_hints):
        return InfrastructureType.RESIDENTIAL

    return InfrastructureType.UNKNOWN


def _temporal_decay(days_old: int, half_life: float = 90.0) -> float:
    """Exponential decay factor. Returns 1.0 for fresh data, approaches 0 for stale."""
    return math.exp(-days_old / half_life)


def _compute_data_completeness(report: IPIntelligenceReport) -> int:
    """Calculate what percentage of feeds actually returned data (0-100)."""
    feeds = [
        report.virustotal.available,
        report.abuseipdb.available,
        report.shodan.available,
        report.greynoise.available,
        report.alienvault.available,
    ]
    return int((sum(feeds) / len(feeds)) * 100)


def _classify(score: int, data_completeness: int) -> RiskClassification:
    """Map a numeric score to a risk classification label.

    If data completeness is below 40%, return INSUFFICIENT_DATA regardless of score
    to prevent false negatives from API failures.
    """
    if data_completeness < 40:
        return RiskClassification.INSUFFICIENT_DATA
    if score <= 20:
        return RiskClassification.BENIGN
    if score <= 50:
        return RiskClassification.SUSPICIOUS
    if score <= 75:
        return RiskClassification.LIKELY_MALICIOUS
    return RiskClassification.MALICIOUS


# ── Main Scoring Function ────────────────────────────────────────────────────


def compute_risk_score(report: IPIntelligenceReport) -> RiskScore:
    """Compute an evidence-aware risk score with separated threat activity and attribution.

    Scoring pipeline:
        1. Detect infrastructure type → set attribution confidence modifier.
        2. Collect signals into categories (DIRECT, CONTEXTUAL, REPUTATION).
        3. Cap each category independently.
        4. Apply corroboration (boost confirmed, dampen isolated).
        5. Compute weighted final score with infrastructure modifier.
        6. Confidence cap: shared infra + no direct evidence = max 35.
        7. Consensus guard: if all signals are from one category, downgrade classification.

    Returns
    -------
    RiskScore
        Full risk assessment with threat_activity_score, attribution_confidence,
        infrastructure_type, data_completeness, and reasoning chain.
    """
    signals: list[ScoringSignal] = []
    conflicts: list[IntelligenceConflict] = []
    reasoning_chain: list[str] = []

    vt = report.virustotal
    abuse = report.abuseipdb
    own = report.ownership
    gn = report.greynoise
    otx = report.alienvault
    shodan = report.shodan

    # ── Step 1: Infrastructure Detection ──────────────────────────────────

    infra_type = _detect_infrastructure_type(report)
    infra_modifier = _INFRA_MODIFIERS[infra_type]
    attribution_confidence = int(infra_modifier * 100)

    if infra_type in (InfrastructureType.SHARED_CLOUD, InfrastructureType.CDN):
        signals.append(ScoringSignal(
            name="Shared Infrastructure",
            weight=0,
            reason=f"Infrastructure classified as {infra_type.value} ({own.asn_description or 'Unknown ASN'}). Attribution confidence reduced to {attribution_confidence}%.",
            category=SignalCategory.INFRASTRUCTURE,
        ))
        reasoning_chain.append(
            f"Infrastructure Analysis: This IP belongs to {infra_type.value.replace('_', ' ')} infrastructure "
            f"({own.asn_description or 'Unknown'}). Shared hosting environments reduce confidence in IP "
            f"ownership attribution, but do not rule out malicious activity."
        )
    elif infra_type == InfrastructureType.VPS:
        signals.append(ScoringSignal(
            name="VPS/Hosting Infrastructure",
            weight=0,
            reason=f"Infrastructure classified as VPS/hosting ({own.asn_description or 'Unknown ASN'}). Attribution confidence elevated to {attribution_confidence}%.",
            category=SignalCategory.INFRASTRUCTURE,
        ))
        reasoning_chain.append(
            "Infrastructure Analysis: This IP is on a VPS/hosting provider. "
            "VPS infrastructure is commonly used by threat actors for dedicated attack infrastructure."
        )
    elif infra_type == InfrastructureType.ENTERPRISE:
        signals.append(ScoringSignal(
            name="Known Enterprise Service",
            weight=0,
            reason=f"GreyNoise RIOT identifies this as a known-good enterprise service{': ' + gn.name if gn.name else ''}.",
            category=SignalCategory.INFRASTRUCTURE,
        ))
        reasoning_chain.append(
            f"Infrastructure Analysis: This IP is a known, trusted enterprise service"
            f"{' (' + gn.name + ')' if gn.name else ''}. False positive risk is extremely high."
        )

    # No ASN found at all
    if not own.asn and not own.org:
        signals.append(ScoringSignal(
            name="Unknown Network",
            weight=3,
            reason="No ASN or organization information found via RDAP",
            category=SignalCategory.CONTEXTUAL,
        ))

    # ── Step 2: Collect Categorized Signals ───────────────────────────────

    # Track which sources flag as malicious vs benign for corroboration
    sources_malicious: list[str] = []
    sources_benign: list[str] = []

    # ── VirusTotal ────────────────────────────────────────────────────────

    if vt.available:
        if vt.malicious > 0:
            sources_malicious.append("virustotal")
            weight = int(min(25, vt.malicious * 3) * SOURCE_CONFIDENCE["virustotal"])
            signals.append(ScoringSignal(
                name="VirusTotal Malicious Detections",
                weight=weight,
                reason=f"{vt.malicious} security vendor(s) flagged this IP as malicious",
                category=SignalCategory.DIRECT_MALICIOUS,
            ))
            reasoning_chain.append(f"Direct evidence: {vt.malicious} security vendors on VirusTotal flagged this IP.")
        else:
            sources_benign.append("virustotal")

        if vt.suspicious > 0:
            weight = int(min(10, vt.suspicious * 2) * SOURCE_CONFIDENCE["virustotal"])
            signals.append(ScoringSignal(
                name="VirusTotal Suspicious Detections",
                weight=weight,
                reason=f"{vt.suspicious} vendor(s) flagged this IP as suspicious",
                category=SignalCategory.CONTEXTUAL,
            ))

        if vt.reputation < -5:
            weight = min(10, abs(vt.reputation))
            signals.append(ScoringSignal(
                name="VirusTotal Negative Reputation",
                weight=weight,
                reason=f"Community reputation score: {vt.reputation}",
                category=SignalCategory.REPUTATION,
            ))

    # ── AbuseIPDB ─────────────────────────────────────────────────────────

    if abuse.available:
        abuse_weight = 0.0
        if abuse.abuse_confidence_score > 70:
            sources_malicious.append("abuseipdb")
            abuse_weight = 20.0
        elif abuse.abuse_confidence_score > 40:
            sources_malicious.append("abuseipdb")
            abuse_weight = 10.0
        else:
            if abuse.total_reports == 0:
                sources_benign.append("abuseipdb")

        if abuse.total_reports > 50:
            abuse_weight += 10.0
        elif abuse.total_reports > 10:
            abuse_weight += 5.0

        # Universal temporal decay
        if abuse_weight > 0 and abuse.last_reported_at:
            try:
                clean_date = abuse.last_reported_at.replace("Z", "+00:00")
                if "." in clean_date:
                    clean_date = clean_date.split(".")[0] + "+00:00"
                dt = datetime.fromisoformat(clean_date)
                days_old = max(0, (datetime.now(timezone.utc) - dt).days)
                decay_factor = _temporal_decay(days_old)
                decayed_weight = int(abuse_weight * decay_factor * SOURCE_CONFIDENCE["abuseipdb"])

                if decayed_weight > 0:
                    signals.append(ScoringSignal(
                        name="AbuseIPDB Reports (Decayed)",
                        weight=decayed_weight,
                        reason=f"Confidence: {abuse.abuse_confidence_score}% | {abuse.total_reports} reports | Last report {days_old}d ago | Decay: {decay_factor:.0%}",
                        category=SignalCategory.DIRECT_MALICIOUS,
                    ))
                    reasoning_chain.append(
                        f"Community abuse telemetry: {abuse.total_reports} reports at {abuse.abuse_confidence_score}% confidence. "
                        f"Temporally decayed to {decay_factor:.0%} strength ({days_old} days old)."
                    )
            except Exception:
                pass

        if abuse.is_whitelisted:
            sources_benign.append("abuseipdb_whitelist")
            signals.append(ScoringSignal(
                name="AbuseIPDB Whitelisted",
                weight=-15,
                reason="IP is whitelisted (known benign, e.g. search engine bot)",
                category=SignalCategory.REPUTATION,
            ))
            reasoning_chain.append("AbuseIPDB flags this IP as whitelisted/benign (likely a known crawler or service).")

    # ── Shodan ────────────────────────────────────────────────────────────

    if shodan.available and shodan.open_ports:
        _SUSPICIOUS_PORTS = {23, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 11211, 27017}
        exposed_suspicious = [p for p in shodan.open_ports if p in _SUSPICIOUS_PORTS]
        if exposed_suspicious:
            port_names = ", ".join(str(p) for p in exposed_suspicious)
            weight = min(10, len(exposed_suspicious) * 3)
            signals.append(ScoringSignal(
                name="Suspicious Exposed Ports",
                weight=weight,
                reason=f"Risky ports exposed: {port_names} (Shodan)",
                category=SignalCategory.CONTEXTUAL,
            ))

        if shodan.vulns:
            weight = min(15, len(shodan.vulns) * 3)
            vuln_sample = ", ".join(shodan.vulns[:5])
            extra = f" (+{len(shodan.vulns) - 5} more)" if len(shodan.vulns) > 5 else ""
            signals.append(ScoringSignal(
                name="Known Vulnerabilities",
                weight=weight,
                reason=f"Shodan reports {len(shodan.vulns)} CVE(s): {vuln_sample}{extra}",
                category=SignalCategory.CONTEXTUAL,
            ))

    # ── GreyNoise ─────────────────────────────────────────────────────────

    if gn.available:
        if gn.riot:
            sources_benign.append("greynoise_riot")
            signals.append(ScoringSignal(
                name="GreyNoise RIOT (Benign Service)",
                weight=-30,
                reason=f"Known-good service{': ' + gn.name if gn.name else ''}",
                category=SignalCategory.REPUTATION,
            ))
            reasoning_chain.append(
                f"GreyNoise RIOT identifies this as a highly trusted service"
                f"{' (' + gn.name + ')' if gn.name else ''}. False positive risk is extremely high."
            )
        elif gn.classification == "benign":
            sources_benign.append("greynoise")
            signals.append(ScoringSignal(
                name="GreyNoise Benign Scanner",
                weight=-15,
                reason="GreyNoise classifies this IP as a benign internet scanner",
                category=SignalCategory.REPUTATION,
            ))
            reasoning_chain.append("GreyNoise observed this IP as a benign internet scanner/researcher.")
        elif gn.classification == "malicious":
            sources_malicious.append("greynoise")
            weight = int(25 * SOURCE_CONFIDENCE["greynoise"])
            signals.append(ScoringSignal(
                name="GreyNoise Malicious Activity",
                weight=weight,
                reason=f"Active malicious scanning{': ' + gn.name if gn.name else ''}",
                category=SignalCategory.DIRECT_MALICIOUS,
            ))
            reasoning_chain.append("GreyNoise actively observes malicious Internet-wide scanning or exploitation from this IP.")

        if gn.cve:
            sources_malicious.append("greynoise_cve")
            weight = int(min(10, len(gn.cve) * 2) * SOURCE_CONFIDENCE["greynoise"])
            cve_sample = ", ".join(gn.cve[:5])
            signals.append(ScoringSignal(
                name="GreyNoise CVE Exploitation",
                weight=weight,
                reason=f"Active exploitation of: {cve_sample}",
                category=SignalCategory.DIRECT_MALICIOUS,
            ))
            reasoning_chain.append(f"Direct evidence: IP observed exploiting specific vulnerabilities ({cve_sample}).")

    # ── AlienVault OTX (flattened to single contextual signal) ────────────

    if otx.available:
        otx_score = 0
        otx_reason_parts = []

        valid_pulses = [p for p in otx.pulses if p.confidence > 0]
        curated = [p for p in valid_pulses if not p.is_auto_generated]
        auto = [p for p in valid_pulses if p.is_auto_generated]

        if curated:
            # Capped: max +8 for curated
            otx_score += min(8, len(curated) * 3)
            otx_reason_parts.append(f"{len(curated)} curated pulse(s)")
        if auto:
            # Capped: max +2 for auto-generated
            otx_score += min(2, len(auto))
            otx_reason_parts.append(f"{len(auto)} auto-generated pulse(s)")

        # Adversary attribution: high-tier contextual, NOT stacked
        if otx.adversary:
            otx_score = max(otx_score, 12)  # override, don't stack
            otx_reason_parts.append(f"threat group: {otx.adversary}")

        if otx_score > 0:
            signals.append(ScoringSignal(
                name="OTX Community Intelligence",
                weight=otx_score,
                reason=f"Single contextual assessment from OTX: {', '.join(otx_reason_parts)}",
                category=SignalCategory.CONTEXTUAL,
            ))
            reasoning_chain.append(
                f"Contextual intelligence: OTX community references this IP in {', '.join(otx_reason_parts)}. "
                f"This is associative, not direct evidence of maliciousness."
            )

    # ── Step 3: Data Completeness ─────────────────────────────────────────

    data_completeness = _compute_data_completeness(report)

    if data_completeness < 40:
        reasoning_chain.append(
            f"WARNING: Only {data_completeness}% of intelligence feeds returned data. "
            f"This assessment has insufficient coverage and should not be trusted."
        )

    # ── Step 4: Categorize & Cap ──────────────────────────────────────────

    direct_raw = sum(s.weight for s in signals if s.category == SignalCategory.DIRECT_MALICIOUS)
    contextual_raw = sum(s.weight for s in signals if s.category == SignalCategory.CONTEXTUAL)
    reputation_raw = sum(s.weight for s in signals if s.category == SignalCategory.REPUTATION)

    direct_capped = min(_CATEGORY_CAPS[SignalCategory.DIRECT_MALICIOUS], max(0, direct_raw))
    contextual_capped = min(_CATEGORY_CAPS[SignalCategory.CONTEXTUAL], max(0, contextual_raw))
    reputation_capped = reputation_raw  # reputation can be negative (benign signals), don't cap at 0

    # ── Step 5: Corroboration ─────────────────────────────────────────────

    unique_malicious_sources = len(set(sources_malicious))
    unique_benign_sources = len(set(sources_benign))
    corroboration_multiplier = 1.0

    if unique_malicious_sources >= 2:
        # Corroborated by multiple independent sources → boost
        corroboration_multiplier = 1.3
        reasoning_chain.append(
            f"Corroboration: Malicious signals confirmed by {unique_malicious_sources} independent sources "
            f"({', '.join(set(sources_malicious))}). Confidence boosted."
        )
    elif unique_malicious_sources == 1 and unique_benign_sources >= 2:
        # Single malicious source contradicted by multiple benign → dampen
        corroboration_multiplier = 0.4
        reasoning_chain.append(
            f"Single-source alert dampened: Only {list(set(sources_malicious))[0]} flags malicious, "
            f"but {unique_benign_sources} sources indicate benign. Likely false positive."
        )
        conflicts.append(IntelligenceConflict(
            severity="medium",
            explanation=f"Isolated malicious signal from {list(set(sources_malicious))[0]} contradicted by {unique_benign_sources} benign indicators."
        ))

    # ── Step 6: Compute Final Score ───────────────────────────────────────

    # Weighted composition: direct evidence dominates, context supplements, reputation adjusts
    raw_score = (direct_capped + contextual_capped + reputation_capped) * corroboration_multiplier

    # Apply infrastructure modifier — reduces score for shared infra, boosts for VPS
    raw_score *= infra_modifier

    # Threat activity score is computed BEFORE infrastructure modifier (pure threat signal)
    threat_activity = int(max(0, min(100, direct_capped + contextual_capped)))

    # ── Step 7: Confidence Caps ───────────────────────────────────────────

    is_shared_infra = infra_type in (InfrastructureType.SHARED_CLOUD, InfrastructureType.CDN)
    has_direct_evidence = direct_capped > 0

    if is_shared_infra and not has_direct_evidence:
        # No direct malicious evidence + shared infrastructure = cap at 35
        if raw_score > 35:
            raw_score = 35
            reasoning_chain.append(
                "Confidence cap applied: Shared infrastructure with no direct malicious evidence. "
                "Maximum score capped at 35 (Suspicious). Direct evidence (scanning, malware, exploits) "
                "would override this cap."
            )

    # ── Step 8: RIOT Override ─────────────────────────────────────────────

    if gn.available and gn.riot and raw_score > 15:
        conflicts.append(IntelligenceConflict(
            severity="high",
            explanation=f"GreyNoise RIOT classifies this as a known-good service ({gn.name}), "
                        f"but other feeds report threat signals. Trusting RIOT — likely false positive."
        ))
        raw_score = min(raw_score, 15)
        reasoning_chain.append(
            f"RIOT override: GreyNoise identifies this as a trusted service ({gn.name}). "
            f"Score capped to prevent false positive classification."
        )

    # ── Step 9: Contradiction Detection ───────────────────────────────────

    if is_shared_infra and has_direct_evidence:
        conflicts.append(IntelligenceConflict(
            severity="high",
            explanation="Direct malicious evidence detected on shared cloud/CDN infrastructure. "
                        "Threat activity is real, but the IP may be ephemeral or shared with legitimate tenants."
        ))

    # ── Step 10: Consensus Guard ──────────────────────────────────────────

    final_score = int(max(0, min(100, raw_score)))
    classification = _classify(final_score, data_completeness)

    # Consensus check: if all positive signals come from a single category, downgrade by one level
    categories_contributing = set(
        s.category for s in signals
        if s.weight > 0 and s.category != SignalCategory.INFRASTRUCTURE
    )
    if len(categories_contributing) == 1 and final_score > 20:
        sole_category = list(categories_contributing)[0]
        if sole_category == SignalCategory.CONTEXTUAL:
            # Contextual-only signals should never push past Suspicious
            if classification in (RiskClassification.LIKELY_MALICIOUS, RiskClassification.MALICIOUS):
                classification = RiskClassification.SUSPICIOUS
                reasoning_chain.append(
                    f"Consensus guard: All positive signals are contextual ({sole_category.value}). "
                    f"Without corroborating direct evidence, classification downgraded to Suspicious."
                )

    if len(signals) == 0:
        reasoning_chain.append("No significant intelligence signals found for this IP.")

    # ── Finalize ──────────────────────────────────────────────────────────

    log.info(
        "Score [%s]: %d (%s) — threat=%d attrib=%d%% infra=%s completeness=%d%% — %d signal(s), %d conflict(s)",
        report.ip, final_score, classification.value,
        threat_activity, attribution_confidence, infra_type.value,
        data_completeness, len(signals), len(conflicts),
    )

    return RiskScore(
        score=final_score,
        classification=classification,
        signals=signals,
        conflicts=conflicts,
        reasoning_chain=reasoning_chain,
        threat_activity_score=threat_activity,
        attribution_confidence=attribution_confidence,
        infrastructure_type=infra_type,
        data_completeness=data_completeness,
    )
