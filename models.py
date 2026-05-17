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
    """Reverse DNS (PTR) information."""

    ptr: Optional[str] = None
    aliases: list[str] = Field(default_factory=list)


# ── Threat intelligence results ───────────────────────────────────────────────


class VirusTotalResult(BaseModel):
    """Parsed VirusTotal IP report."""

    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    reputation: int = 0
    historic_domains: list[str] = Field(default_factory=list)
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


# ── Scoring ───────────────────────────────────────────────────────────────────


class ScoringSignal(BaseModel):
    """One contributing signal to the overall risk score."""

    name: str
    weight: int
    reason: str


class RiskScore(BaseModel):
    """Computed risk assessment."""

    score: int = 0
    classification: RiskClassification = RiskClassification.BENIGN
    signals: list[ScoringSignal] = Field(default_factory=list)


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

    # Risk assessment
    risk: RiskScore = Field(default_factory=RiskScore)

    # Metadata
    errors: list[str] = Field(default_factory=list)
    query_duration_s: float = 0.0
