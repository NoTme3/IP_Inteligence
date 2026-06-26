"""Pydantic data models used across the entire pipeline."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ── Enums ─────────────────────────────────────────────────────────────────────


class RiskClassification(str, Enum):
    BENIGN = "Benign"
    SUSPICIOUS = "Suspicious"
    LIKELY_MALICIOUS = "Likely Malicious"
    MALICIOUS = "Malicious"
    INSUFFICIENT_DATA = "Insufficient Data"


class SignalCategory(str, Enum):
    """Evidence classification tier for scoring signals."""
    DIRECT_MALICIOUS = "direct_malicious"
    CONTEXTUAL = "contextual"
    REPUTATION = "reputation"
    INFRASTRUCTURE = "infrastructure"


class InfrastructureType(str, Enum):
    """Infrastructure classification for attribution confidence."""
    SHARED_CLOUD = "shared_cloud"
    CDN = "cdn"
    RESIDENTIAL = "residential"
    VPS = "vps"
    ENTERPRISE = "enterprise"
    UNKNOWN = "unknown"


# ── Input ─────────────────────────────────────────────────────────────────────


class IPInput(BaseModel):
    """A validated IP address ready for enrichment."""

    ip: str
    ip_version: int  # 4 or 6
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ── Enrichment results ────────────────────────────────────────────────────────


class OwnershipInfo(BaseModel):
    """Network ownership data from RDAP."""

    asn: Optional[str] = None
    asn_description: Optional[str] = None
    org: Optional[str] = None
    cidr: Optional[str] = None
    country: Optional[str] = None
    rir: Optional[str] = None
    netblock_start: Optional[str] = None
    netblock_end: Optional[str] = None


class DNSInfo(BaseModel):
    """Reverse DNS (PTR) and full DNS record information."""

    ptr: Optional[str] = None
    aliases: list[str] = Field(default_factory=list)
    # Full DNS records (populated when PTR resolves to a domain)
    a_records: list[str] = Field(default_factory=list)
    aaaa_records: list[str] = Field(default_factory=list)
    mx_records: list[str] = Field(default_factory=list)
    ns_records: list[str] = Field(default_factory=list)
    txt_records: list[str] = Field(default_factory=list)
    fcrdns_valid: Optional[bool] = None  # Forward-Confirmed Reverse DNS


# ── Passive DNS ───────────────────────────────────────────────────────────────


class PassiveDNSEntry(BaseModel):
    """A single passive DNS resolution record."""

    hostname: str
    resolved_date: Optional[str] = None  # ISO date string from VT


# ── Sanctions ─────────────────────────────────────────────────────────────────


class SanctionsResult(BaseModel):
    """OFAC / OpenSanctions cross-check result."""

    is_sanctioned: bool = False
    matched_entity: str = ""
    match_score: float = 0.0
    sanctions_program: str = ""


# ── SSL/TLS ───────────────────────────────────────────────────────────────────


class SSLResult(BaseModel):
    """SSL/TLS certificate inspection result."""

    has_ssl: bool = False
    issuer: str = ""
    subject: str = ""
    sans: list[str] = Field(default_factory=list)
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    is_expired: bool = False
    is_self_signed: bool = False
    key_size: int = 0
    serial_number: str = ""
    signature_algorithm: str = ""


# ── CVE Details ───────────────────────────────────────────────────────────────


class CVEDetail(BaseModel):
    """Enriched CVE detail from NVD."""

    cve_id: str
    cvss_score: float = 0.0
    severity: str = ""  # CRITICAL, HIGH, MEDIUM, LOW
    description: str = ""
    affected_products: list[str] = Field(default_factory=list)


# ── Country Risk ──────────────────────────────────────────────────────────────


class CountryRiskInfo(BaseModel):
    """Geopolitical risk assessment for the IP's country."""

    risk_tier: str = "unknown"  # critical, high, medium, low, minimal
    risk_label: str = ""
    factors: list[str] = Field(default_factory=list)


# ── Threat intelligence results ───────────────────────────────────────────────


class VirusTotalResult(BaseModel):
    """Parsed VirusTotal IP report."""

    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    reputation: int = 0
    historic_domains: list[str] = Field(default_factory=list)
    passive_dns: list[PassiveDNSEntry] = Field(default_factory=list)
    as_owner: Optional[str] = None
    country: Optional[str] = None
    available: bool = True  # False if API key missing or query failed


class AbuseIPDBResult(BaseModel):
    """Parsed AbuseIPDB check result."""

    abuse_confidence_score: int = 0
    total_reports: int = 0
    is_whitelisted: bool = False
    isp: Optional[str] = None
    domain: Optional[str] = None
    usage_type: Optional[str] = None
    country_code: Optional[str] = None
    last_reported_at: Optional[str] = None
    available: bool = True


class ShodanService(BaseModel):
    """A single service/port detected by Shodan."""

    port: int
    protocol: str = "tcp"
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    cpe: list[str] = Field(default_factory=list)


class ShodanResult(BaseModel):
    """Parsed Shodan host intelligence."""

    open_ports: list[int] = Field(default_factory=list)
    services: list[ShodanService] = Field(default_factory=list)
    os: Optional[str] = None
    hostnames: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    vulns: list[str] = Field(default_factory=list)
    org: Optional[str] = None
    isp: Optional[str] = None
    last_update: Optional[str] = None
    available: bool = True
    source: str = ""  # 'shodan_api' or 'internetdb'


class GreyNoiseResult(BaseModel):
    """Parsed GreyNoise classification result."""

    seen: bool = False
    classification: str = "unknown"  # benign, malicious, unknown
    name: str = ""  # Actor name if identified
    riot: bool = False  # True = known-good service (Rule It Out)
    message: str = ""
    last_seen: Optional[str] = None
    tags: list[str] = Field(default_factory=list)
    cve: list[str] = Field(default_factory=list)
    category: str = ""  # isp, business, hosting, etc.
    available: bool = True


class OTXPulseAssessment(BaseModel):
    """Quality assessment of a single OTX pulse."""

    pulse_name: str
    pulse_age_days: int
    is_auto_generated: bool
    confidence: float
    evidence_type: str


class AlienVaultResult(BaseModel):
    """Parsed AlienVault OTX result."""

    pulse_count: int = 0
    reputation: int = 0
    malware_count: int = 0
    malware_families: list[str] = Field(default_factory=list)
    pulse_names: list[str] = Field(default_factory=list)  # Threat campaign names
    adversary: str = ""  # Known threat group attribution
    country: Optional[str] = None
    pulses: list[OTXPulseAssessment] = Field(default_factory=list)
    available: bool = True


# ── Scoring ───────────────────────────────────────────────────────────────────


class ScoringSignal(BaseModel):
    """One contributing signal to the overall risk score."""

    name: str
    weight: int
    reason: str
    category: SignalCategory = SignalCategory.CONTEXTUAL


class IntelligenceConflict(BaseModel):
    """A detected conflict in the intelligence signals."""

    severity: str  # high, medium, low
    explanation: str


class RiskScore(BaseModel):
    """Computed risk assessment."""

    score: int = 0
    classification: RiskClassification = RiskClassification.BENIGN
    signals: list[ScoringSignal] = Field(default_factory=list)
    conflicts: list[IntelligenceConflict] = Field(default_factory=list)
    reasoning_chain: list[str] = Field(default_factory=list)

    # New evidence-aware fields
    threat_activity_score: int = 0
    attribution_confidence: int = 100  # 0-100%
    infrastructure_type: InfrastructureType = InfrastructureType.UNKNOWN
    data_completeness: int = 0  # 0-100% — how many feeds responded


# ── Full report ───────────────────────────────────────────────────────────────


class IPIntelligenceReport(BaseModel):
    """Complete intelligence report for a single IP address."""

    ip: str
    ip_version: int
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Enrichment
    ownership: OwnershipInfo = Field(default_factory=OwnershipInfo)
    dns: DNSInfo = Field(default_factory=DNSInfo)

    # Threat intel
    virustotal: VirusTotalResult = Field(default_factory=VirusTotalResult)
    abuseipdb: AbuseIPDBResult = Field(default_factory=AbuseIPDBResult)
    shodan: ShodanResult = Field(default_factory=ShodanResult)
    greynoise: GreyNoiseResult = Field(default_factory=GreyNoiseResult)
    alienvault: AlienVaultResult = Field(default_factory=AlienVaultResult)

    # New enrichment layers
    sanctions: SanctionsResult = Field(default_factory=SanctionsResult)
    ssl: SSLResult = Field(default_factory=SSLResult)
    cve_details: list[CVEDetail] = Field(default_factory=list)
    country_risk: CountryRiskInfo = Field(default_factory=CountryRiskInfo)

    # Risk assessment
    risk: RiskScore = Field(default_factory=RiskScore)

    # Campaign correlation
    campaign_tags: list[str] = Field(default_factory=list)

    # Metadata
    errors: list[str] = Field(default_factory=list)
    query_duration_s: float = 0.0
