"""Country risk scoring based on geopolitical and cyber threat data.

Uses a static curated dataset of country risk tiers derived from:
- OFAC sanctioned countries
- FATF grey/black list
- Known APT origin countries
- Active conflict zones
- High cybercrime activity regions

No external API calls — instant lookup.
"""

from __future__ import annotations

from typing import Optional

from models import CountryRiskInfo
from utils.logger import get_logger

log = get_logger("country_risk")

# ── Country risk database ─────────────────────────────────────────────────────
# Format: country_code → (tier, label, [factors])

_COUNTRY_RISK: dict[str, tuple[str, str, list[str]]] = {
    # ── Critical (sanctioned / comprehensive embargo) ──
    "KP": ("critical", "North Korea", ["OFAC comprehensive sanctions", "Known APT origin (Lazarus Group)", "Active nuclear proliferation"]),
    "IR": ("critical", "Iran", ["OFAC comprehensive sanctions", "Known APT origin (APT33, APT34, APT35)", "Active cyber warfare"]),
    "SY": ("critical", "Syria", ["OFAC comprehensive sanctions", "Active conflict zone", "State-sponsored cyber operations"]),
    "CU": ("critical", "Cuba", ["OFAC comprehensive sanctions", "Restricted trade partner"]),

    # ── High (FATF grey/black, active conflict, major APT origin) ──
    "RU": ("high", "Russia", ["OFAC sectoral sanctions", "Known APT origin (APT28, APT29, Sandworm)", "Active cyber warfare", "FATF countermeasures"]),
    "CN": ("high", "China", ["Known APT origin (APT1, APT10, APT41)", "State-sponsored cyber espionage", "IP theft operations"]),
    "BY": ("high", "Belarus", ["OFAC sanctions", "Russian ally in active conflict", "Known proxy infrastructure"]),
    "MM": ("high", "Myanmar", ["FATF grey list", "Active conflict zone", "Scam compound operations"]),
    "SD": ("high", "Sudan", ["Active conflict zone", "UN sanctions", "Humanitarian crisis"]),
    "YE": ("high", "Yemen", ["Active conflict zone", "OFAC targeted sanctions (Houthis)"]),
    "VE": ("high", "Venezuela", ["OFAC sectoral sanctions", "Economic instability"]),

    # ── Medium (elevated cyber threat, FATF concerns, regional tension) ──
    "UA": ("medium", "Ukraine", ["Active conflict zone", "Elevated cyber activity (both offensive and defensive)"]),
    "PK": ("medium", "Pakistan", ["FATF grey list (intermittent)", "Elevated cyber crime activity"]),
    "NG": ("medium", "Nigeria", ["FATF grey list", "High business email compromise (BEC) origin", "Elevated cyber fraud"]),
    "VN": ("medium", "Vietnam", ["Known APT origin (APT32/OceanLotus)", "State-sponsored espionage"]),
    "LB": ("medium", "Lebanon", ["Regional tension zone", "Non-state actor operations"]),
    "IQ": ("medium", "Iraq", ["Post-conflict instability", "Militia cyber operations"]),
    "AF": ("medium", "Afghanistan", ["Post-conflict instability", "Limited cyber governance"]),
    "LY": ("medium", "Libya", ["Active conflict", "Limited governance"]),
    "SO": ("medium", "Somalia", ["Active conflict", "Al-Shabaab operations", "Limited cyber governance"]),
    "ET": ("medium", "Ethiopia", ["Internal conflict", "Internet censorship"]),
    "BD": ("medium", "Bangladesh", ["Elevated cyber crime", "Growing BEC activity"]),
    "KH": ("medium", "Cambodia", ["Scam compound operations", "Cyber crime haven"]),
    "LA": ("medium", "Laos", ["Scam compound hub", "Limited cyber governance"]),
    "TZ": ("medium", "Tanzania", ["FATF grey list"]),
    "JM": ("medium", "Jamaica", ["FATF grey list", "Elevated financial crime"]),
    "HT": ("medium", "Haiti", ["FATF grey list", "Political instability"]),

    # ── Low (some concerns but generally stable) ──
    "TR": ("low", "Turkey", ["NATO member", "Occasional hacktivist activity", "Regional geopolitical tensions"]),
    "IN": ("low", "India", ["Occasional state-sponsored activity", "Growing cyber crime", "Large attack surface"]),
    "BR": ("low", "Brazil", ["Elevated financial cyber crime", "Banking trojan origin"]),
    "ID": ("low", "Indonesia", ["Growing cyber crime activity", "Hacktivist groups"]),
    "PH": ("low", "Philippines", ["Scam operations", "BEC activity"]),
    "RO": ("low", "Romania", ["Historical cyber crime hub", "Improving governance"]),
    "BG": ("low", "Bulgaria", ["Hosting jurisdiction for bulletproof providers"]),
}

# All other countries default to "minimal"


def assess_country_risk(country_code: Optional[str]) -> CountryRiskInfo:
    """Assess geopolitical/cyber risk for a given country code.

    Parameters
    ----------
    country_code:
        ISO 3166-1 alpha-2 country code (e.g., "US", "RU", "CN").

    Returns
    -------
    CountryRiskInfo
        Risk tier, label, and contributing factors.
    """
    if not country_code or country_code.upper() in ("", "UNKNOWN", "N/A"):
        return CountryRiskInfo()

    code = country_code.upper().strip()
    entry = _COUNTRY_RISK.get(code)

    if entry:
        tier, label, factors = entry
        log.debug("Country risk: %s (%s) → %s", code, label, tier)
        return CountryRiskInfo(
            risk_tier=tier,
            risk_label=f"{label} — {tier.title()} Risk",
            factors=factors,
        )

    # Default: minimal risk
    return CountryRiskInfo(
        risk_tier="minimal",
        risk_label="Minimal Risk",
        factors=[],
    )
