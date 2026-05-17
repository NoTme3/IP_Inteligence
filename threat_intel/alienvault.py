"""AlienVault OTX (Open Threat Exchange) — APT and malware campaign context.

The OTX API is free and provides:
  - Pulse count: how many threat intelligence "pulses" mention this IP
  - Malware associations
  - Known threat group attributions
  - Country / geo data

No API key is required for basic lookups, but a key enables higher rate limits.
"""

from __future__ import annotations

import datetime
import httpx

from models import AlienVaultResult, OTXPulseAssessment
from utils.logger import get_logger

log = get_logger("alienvault")

_BASE_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4"


async def query_alienvault(
    ip: str,
    client: httpx.AsyncClient,
    *,
    api_key: str = "",
) -> AlienVaultResult:
    """Query AlienVault OTX for an IP address.

    Parameters
    ----------
    ip:
        The IP address to look up.
    client:
        A shared ``httpx.AsyncClient`` instance.
    api_key:
        Optional OTX API key (improves rate limits).

    Returns
    -------
    AlienVaultResult
        Pulse count, malware families, and reputation data.
    """
    headers = {"accept": "application/json"}
    if api_key:
        headers["X-OTX-API-KEY"] = api_key

    try:
        log.debug("Querying AlienVault OTX for %s", ip)

        # Fetch general info + pulse info concurrently
        general_url = f"{_BASE_URL}/{ip}/general"
        malware_url = f"{_BASE_URL}/{ip}/malware"

        import asyncio
        gen_task = client.get(general_url, headers=headers)
        mal_task = client.get(malware_url, headers=headers)

        responses = await asyncio.gather(gen_task, mal_task, return_exceptions=True)

        # Parse general info
        pulse_count = 0
        reputation_score = 0
        country = None
        pulse_names: list[str] = []
        adversary: str = ""

        if not isinstance(responses[0], Exception):
            gen_resp = responses[0]
            if gen_resp.status_code == 200:
                gen_data = gen_resp.json()

                pulse_info = gen_data.get("pulse_info", {})
                pulse_count = pulse_info.get("count", 0)

                now = datetime.datetime.now(datetime.timezone.utc)
                parsed_pulses = []

                # Extract pulse names (threat campaign names)
                for pulse in pulse_info.get("pulses", [])[:20]:
                    name = pulse.get("name", "")
                    author = pulse.get("author_name", "").lower()
                    created = pulse.get("created", "")
                    
                    age_days = 0
                    if created:
                        try:
                            # Ensure we can parse the ISO format easily
                            clean_date = created.replace("Z", "+00:00")
                            # Handle weird precision issues
                            if "." in clean_date:
                                clean_date = clean_date.split(".")[0] + "+00:00"
                            dt = datetime.datetime.fromisoformat(clean_date)
                            age_days = max(0, (now - dt).days)
                        except Exception:
                            age_days = 0

                    # Heuristic for auto-generated
                    is_auto = False
                    if "alienvault" in author or "bot" in author or "bulk" in name.lower() or "auto" in name.lower():
                        is_auto = True

                    evidence_type = "unknown"
                    name_lower = name.lower()
                    if any(x in name_lower for x in ["c2", "malware", "cobalt strike", "ransomware", "trojan"]):
                        evidence_type = "direct_malicious"
                    elif any(x in name_lower for x in ["scanner", "bruteforce", "ssh", "masscan"]):
                        evidence_type = "direct_malicious"
                    else:
                        evidence_type = "historical_reference"

                    # Calculate confidence
                    confidence = 100.0
                    if is_auto:
                        confidence -= 50.0
                    if age_days > 180:
                        confidence -= 70.0 # Stale pulse penalty

                    confidence = max(0.0, confidence)
                    
                    if name:
                        parsed_pulses.append(OTXPulseAssessment(
                            pulse_name=name,
                            pulse_age_days=age_days,
                            is_auto_generated=is_auto,
                            confidence=confidence,
                            evidence_type=evidence_type
                        ))

                    if name and confidence > 0:
                        pulse_names.append(name)
                        
                    # Check for adversary attribution (only if confidence is high)
                    adv = pulse.get("adversary", "")
                    if adv and not adversary and confidence > 30:
                        adversary = adv

                reputation_score = gen_data.get("reputation", 0)
                country = gen_data.get("country_code")
        else:
            log.error("AlienVault general query failed for %s: %s", ip, responses[0])

        # Parse malware info
        malware_families: list[str] = []
        malware_count = 0

        if not isinstance(responses[1], Exception):
            mal_resp = responses[1]
            if mal_resp.status_code == 200:
                mal_data = mal_resp.json()
                mal_list = mal_data.get("data", [])
                malware_count = len(mal_list)
                seen_families = set()
                for entry in mal_list[:20]:
                    # Try to extract malware hash/family
                    family = entry.get("hash", "")
                    if family and family not in seen_families:
                        seen_families.add(family)
                        malware_families.append(family)
        else:
            log.error("AlienVault malware query failed for %s: %s", ip, responses[1])

        result = AlienVaultResult(
            pulse_count=pulse_count,
            reputation=reputation_score,
            malware_count=malware_count,
            malware_families=malware_families[:5],
            pulse_names=pulse_names[:5],
            adversary=adversary,
            country=country,
            pulses=parsed_pulses,
            available=True,
        )

        log.info(
            "AlienVault OTX [%s]: pulses=%d malware=%d adversary=%s",
            ip,
            result.pulse_count,
            result.malware_count,
            result.adversary or "none",
        )
        return result

    except httpx.HTTPStatusError as exc:
        log.error(
            "AlienVault HTTP %d for %s: %s",
            exc.response.status_code,
            ip,
            exc.response.text[:200],
        )
        return AlienVaultResult(available=False)

    except Exception as exc:
        log.error("AlienVault error for %s: %s", ip, exc)
        return AlienVaultResult(available=False)
