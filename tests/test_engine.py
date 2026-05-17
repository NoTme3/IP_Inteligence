"""Tests for the evidence-aware scoring engine.

Validates:
    1. Shared infrastructure reduces attribution, NOT score
    2. Direct malicious evidence bypasses confidence caps
    3. Bulletproof hosting gets elevated attribution
    4. OTX contextual-only cannot push past Suspicious
    5. Insufficient data returns INSUFFICIENT_DATA classification
    6. Corroboration dampens isolated malicious signals
"""

import pytest
from models import (
    IPIntelligenceReport,
    OwnershipInfo,
    DNSInfo,
    VirusTotalResult,
    AbuseIPDBResult,
    ShodanResult,
    GreyNoiseResult,
    AlienVaultResult,
    OTXPulseAssessment,
    RiskClassification,
    InfrastructureType,
    SignalCategory,
)
from scoring.engine import compute_risk_score


class TestSharedInfrastructure:
    """Shared infra should reduce attribution confidence, not erase evidence."""

    def test_cloudflare_benign_no_flat_penalty(self):
        """Cloudflare IP with no malicious signals should be Benign, NOT score < 0."""
        report = IPIntelligenceReport(
            ip="1.1.1.1",
            ip_version=4,
            ownership=OwnershipInfo(asn="13335", asn_description="CLOUDFLARENET - Cloudflare, Inc., US"),
        )
        risk = compute_risk_score(report)
        assert risk.score == 0
        assert risk.infrastructure_type == InfrastructureType.CDN
        assert risk.attribution_confidence < 100
        # No -35 penalty signal should exist
        assert not any(s.weight == -35 for s in risk.signals)

    def test_aws_with_malicious_vt_bypasses_cap(self):
        """AWS IP with strong VT detections should still score high (direct evidence bypasses cap)."""
        report = IPIntelligenceReport(
            ip="3.4.5.6",
            ip_version=4,
            ownership=OwnershipInfo(asn="16509", asn_description="AMAZON-02 - Amazon.com, Inc., US"),
            virustotal=VirusTotalResult(malicious=10, available=True),
            abuseipdb=AbuseIPDBResult(available=True),
            shodan=ShodanResult(available=False),  # Not all feeds available
            greynoise=GreyNoiseResult(classification="malicious", seen=True, available=True),
            alienvault=AlienVaultResult(available=True),
        )
        risk = compute_risk_score(report)
        assert risk.infrastructure_type == InfrastructureType.SHARED_CLOUD
        assert risk.attribution_confidence < 100
        # Direct evidence should push score above cap of 35
        assert risk.score > 35
        assert risk.threat_activity_score > 0


class TestBulletproofHosting:
    """Bulletproof/VPS hosting should have elevated attribution confidence."""

    def test_bulletproof_high_attribution(self):
        report = IPIntelligenceReport(
            ip="185.0.0.1",
            ip_version=4,
            ownership=OwnershipInfo(asn_description="BULLETPROOF-HOSTING-AS"),
            virustotal=VirusTotalResult(malicious=5, available=True),
            abuseipdb=AbuseIPDBResult(available=True),
            greynoise=GreyNoiseResult(available=True),
            alienvault=AlienVaultResult(available=True),
            shodan=ShodanResult(available=True),
        )
        risk = compute_risk_score(report)
        assert risk.infrastructure_type == InfrastructureType.VPS
        assert risk.attribution_confidence > 100  # 115%


class TestOTXAntiInflation:
    """OTX should contribute ONE contextual score, not multiple stacked scores."""

    def test_otx_only_cannot_exceed_suspicious(self):
        """If OTX is the only source of positive signals, classification should not exceed Suspicious."""
        report = IPIntelligenceReport(
            ip="10.0.0.1",
            ip_version=4,
            virustotal=VirusTotalResult(available=True),  # available but clean
            abuseipdb=AbuseIPDBResult(available=True),
            greynoise=GreyNoiseResult(available=True),
            alienvault=AlienVaultResult(
                pulse_count=20,
                available=True,
                adversary="APT28",
                pulses=[
                    OTXPulseAssessment(pulse_name=f"Pulse {i}", pulse_age_days=10, is_auto_generated=False, confidence=0.8, evidence_type="curated")
                    for i in range(10)
                ],
            ),
            shodan=ShodanResult(available=True),
        )
        risk = compute_risk_score(report)
        # OTX-only should be capped by consensus guard
        assert risk.classification in (RiskClassification.BENIGN, RiskClassification.SUSPICIOUS)
        # Should NOT be Likely Malicious or Malicious
        assert risk.classification not in (RiskClassification.LIKELY_MALICIOUS, RiskClassification.MALICIOUS)

    def test_otx_single_signal(self):
        """OTX should produce at most ONE scoring signal regardless of pulse count."""
        report = IPIntelligenceReport(
            ip="10.0.0.2",
            ip_version=4,
            alienvault=AlienVaultResult(
                pulse_count=50,
                available=True,
                malware_count=10,
                adversary="Lazarus",
                pulses=[
                    OTXPulseAssessment(pulse_name=f"Auto {i}", pulse_age_days=5, is_auto_generated=True, confidence=0.3, evidence_type="auto")
                    for i in range(30)
                ] + [
                    OTXPulseAssessment(pulse_name=f"Curated {i}", pulse_age_days=5, is_auto_generated=False, confidence=0.9, evidence_type="curated")
                    for i in range(20)
                ],
            ),
        )
        risk = compute_risk_score(report)
        otx_signals = [s for s in risk.signals if "OTX" in s.name]
        assert len(otx_signals) == 1  # single flattened signal


class TestInsufficientData:
    """When too few feeds respond, classification should be INSUFFICIENT_DATA."""

    def test_only_one_feed_available(self):
        report = IPIntelligenceReport(
            ip="192.168.1.1",
            ip_version=4,
            virustotal=VirusTotalResult(available=True),
            abuseipdb=AbuseIPDBResult(available=False),
            shodan=ShodanResult(available=False),
            greynoise=GreyNoiseResult(available=False),
            alienvault=AlienVaultResult(available=False),
        )
        # Only VT available = 20% completeness
        risk = compute_risk_score(report)
        assert risk.classification == RiskClassification.INSUFFICIENT_DATA
        assert risk.data_completeness < 40


class TestCorroboration:
    """Signals contradicted by multiple benign sources should be dampened."""

    def test_isolated_malicious_dampened(self):
        """One malicious source + two benign sources = dampened score."""
        report = IPIntelligenceReport(
            ip="4.4.4.4",
            ip_version=4,
            virustotal=VirusTotalResult(malicious=2, available=True),  # weak malicious
            abuseipdb=AbuseIPDBResult(available=True, total_reports=0, abuse_confidence_score=0),  # clean
            greynoise=GreyNoiseResult(available=True, classification="benign", seen=True),  # clean
            alienvault=AlienVaultResult(available=True),
            shodan=ShodanResult(available=True),
        )
        risk = compute_risk_score(report)
        # Corroboration should dampen: only VT flags malicious, abuseipdb + greynoise say benign
        assert risk.score < 20  # should be dampened below Suspicious threshold
        assert any("dampened" in r.lower() or "single-source" in r.lower() for r in risk.reasoning_chain)


class TestRIOTOverride:
    """GreyNoise RIOT should override false positives."""

    def test_riot_caps_score(self):
        report = IPIntelligenceReport(
            ip="8.8.8.8",
            ip_version=4,
            ownership=OwnershipInfo(asn_description="Google LLC"),
            virustotal=VirusTotalResult(malicious=3, available=True),
            greynoise=GreyNoiseResult(riot=True, name="Google DNS", available=True),
            abuseipdb=AbuseIPDBResult(available=True),
            alienvault=AlienVaultResult(available=True),
            shodan=ShodanResult(available=True),
        )
        risk = compute_risk_score(report)
        assert risk.score <= 15
        assert risk.infrastructure_type == InfrastructureType.ENTERPRISE
        assert len(risk.conflicts) > 0
