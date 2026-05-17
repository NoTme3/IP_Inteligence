"""SQLite persistence via aiosqlite with upsert support."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

import aiosqlite

from ip_intel.config import settings
from ip_intel.models import IPIntelligenceReport
from ip_intel.utils.logger import get_logger

log = get_logger("database")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS ip_intelligence (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ip              TEXT    NOT NULL UNIQUE,
    ip_version      INTEGER,
    asn             TEXT,
    org             TEXT,
    country         TEXT,
    cidr            TEXT,
    rir             TEXT,
    ptr             TEXT,
    ports           TEXT    DEFAULT '[]',
    services        TEXT    DEFAULT '[]',
    threat_data     TEXT    DEFAULT '{}',
    score           INTEGER DEFAULT 0,
    classification  TEXT    DEFAULT 'Benign',
    signals         TEXT    DEFAULT '[]',
    raw_data        TEXT    DEFAULT '{}',
    created_at      TEXT    DEFAULT (datetime('now')),
    updated_at      TEXT    DEFAULT (datetime('now'))
);
"""


class Database:
    """Async SQLite wrapper for IP intelligence storage."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = db_path or settings.db_path
        self._conn: Optional[aiosqlite.Connection] = None

    async def connect(self) -> None:
        """Open the database and ensure the schema exists."""
        log.debug("Connecting to database: %s", self.db_path)
        self._conn = await aiosqlite.connect(self.db_path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.execute("PRAGMA journal_mode=WAL")
        await self._conn.executescript(_SCHEMA)
        await self._conn.commit()
        log.info("Database ready: %s", self.db_path)

    async def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            await self._conn.close()
            self._conn = None
            log.debug("Database connection closed")

    async def upsert_report(self, report: IPIntelligenceReport) -> None:
        """Insert or update an IP intelligence report."""
        assert self._conn is not None, "Database not connected"

        threat_data = {
            "virustotal": report.virustotal.model_dump(),
            "abuseipdb": report.abuseipdb.model_dump(),
        }
        signals = [s.model_dump() for s in report.risk.signals]
        raw = report.model_dump(mode="json")

        await self._conn.execute(
            """
            INSERT INTO ip_intelligence
                (ip, ip_version, asn, org, country, cidr, rir, ptr,
                 threat_data, score, classification, signals, raw_data,
                 created_at, updated_at)
            VALUES
                (?, ?, ?, ?, ?, ?, ?, ?,
                 ?, ?, ?, ?, ?,
                 ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                ip_version     = excluded.ip_version,
                asn            = excluded.asn,
                org            = excluded.org,
                country        = excluded.country,
                cidr           = excluded.cidr,
                rir            = excluded.rir,
                ptr            = excluded.ptr,
                threat_data    = excluded.threat_data,
                score          = excluded.score,
                classification = excluded.classification,
                signals        = excluded.signals,
                raw_data       = excluded.raw_data,
                updated_at     = excluded.updated_at
            """,
            (
                report.ip,
                report.ip_version,
                report.ownership.asn,
                report.ownership.org,
                report.ownership.country,
                report.ownership.cidr,
                report.ownership.rir,
                report.dns.ptr,
                json.dumps(threat_data, default=str),
                report.risk.score,
                report.risk.classification.value,
                json.dumps(signals, default=str),
                json.dumps(raw, default=str),
                datetime.now(timezone.utc).isoformat(),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        await self._conn.commit()
        log.debug("Upserted report for %s", report.ip)

    async def get_by_ip(self, ip: str) -> Optional[dict]:
        """Retrieve a stored report by IP address."""
        assert self._conn is not None, "Database not connected"
        cursor = await self._conn.execute(
            "SELECT * FROM ip_intelligence WHERE ip = ?", (ip,)
        )
        row = await cursor.fetchone()
        if row:
            return dict(row)
        return None

    async def get_all(self) -> list[dict]:
        """Retrieve all stored reports."""
        assert self._conn is not None, "Database not connected"
        cursor = await self._conn.execute(
            "SELECT * FROM ip_intelligence ORDER BY score DESC"
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    async def get_by_classification(self, classification: str) -> list[dict]:
        """Retrieve reports matching a classification label."""
        assert self._conn is not None, "Database not connected"
        cursor = await self._conn.execute(
            "SELECT * FROM ip_intelligence WHERE classification = ? ORDER BY score DESC",
            (classification,),
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
