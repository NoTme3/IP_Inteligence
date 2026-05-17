"""Application configuration loaded from environment variables / .env file."""

from __future__ import annotations

import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


# Resolve the project root (where .env lives)
_PROJECT_ROOT = Path(__file__).resolve().parent


class Settings(BaseSettings):
    """Central configuration – values are read from a ``.env`` file or the
    process environment.  Required keys will raise a clear error on startup
    if they are missing.
    """

    model_config = SettingsConfigDict(
        env_file=os.getenv("IP_INTEL_ENV", str(_PROJECT_ROOT / ".env")),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── API Keys ──────────────────────────────────────────────────────────
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    shodan_api_key: str = ""

    # ── Behaviour ─────────────────────────────────────────────────────────
    cache_ttl: int = 86400  # seconds (default 24 h)
    db_path: str = str(_PROJECT_ROOT / "ip_intel.db")
    log_level: str = "INFO"

    # ── Rate-limit budgets (requests per minute) ──────────────────────────
    vt_rpm: int = 4          # VirusTotal free-tier: 4 req / min
    abuseipdb_rpm: int = 15  # AbuseIPDB: ~1 000 / day → conservative
    shodan_rpm: int = 60     # Shodan: ~1 req / sec for paid plans

    # ── Network ───────────────────────────────────────────────────────────
    http_timeout: int = 30   # seconds
    max_concurrency: int = 5

    def has_virustotal(self) -> bool:
        return bool(self.virustotal_api_key)

    def has_abuseipdb(self) -> bool:
        return bool(self.abuseipdb_api_key)

    def has_shodan(self) -> bool:
        return bool(self.shodan_api_key)


# Singleton – import ``settings`` from any module
settings = Settings()
