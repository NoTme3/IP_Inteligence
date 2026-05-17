"""FastAPI backend for IP Intelligence — works on Vercel and locally.

Endpoints:
    POST /api/analyze        — Analyze IPs, return all results as JSON
    POST /api/analyze/stream — Analyze IPs, stream results via SSE
    GET  /api/health         — Health check
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import sys
import time
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

# ── Ensure ip_intel package is importable ─────────────────────────────────────
_project_root = Path(__file__).resolve().parent.parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from ip_intel.core.pipeline import enrich_single_web
from ip_intel.models import IPIntelligenceReport
from ip_intel.utils.http_client import create_client

# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="IP Intelligence",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Constants ─────────────────────────────────────────────────────────────────

MAX_IPS_PER_REQUEST = 10


# ── Request / Response Models ─────────────────────────────────────────────────


class APIKeys(BaseModel):
    virustotal: str = ""
    abuseipdb: str = ""
    shodan: str = ""


class AnalyzeRequest(BaseModel):
    ips: list[str] = Field(..., min_length=1, max_length=MAX_IPS_PER_REQUEST)
    keys: APIKeys = Field(default_factory=APIKeys)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _validate_ip(ip: str) -> Optional[str]:
    """Validate and normalize an IP address. Returns None if invalid."""
    ip = ip.strip()
    if not ip:
        return None
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return None


# ── Routes ────────────────────────────────────────────────────────────────────


@app.get("/api/health")
async def health():
    return {"status": "ok", "max_ips": MAX_IPS_PER_REQUEST}


@app.post("/api/analyze")
async def analyze(req: AnalyzeRequest):
    """Analyze a batch of IPs and return all results at once."""
    # Validate IPs
    valid_ips = []
    invalid_ips = []
    for raw in req.ips:
        normalized = _validate_ip(raw)
        if normalized:
            valid_ips.append(normalized)
        else:
            invalid_ips.append(raw)

    if not valid_ips:
        return JSONResponse(
            status_code=400,
            content={"error": "No valid IP addresses provided", "invalid": invalid_ips},
        )

    # Deduplicate
    valid_ips = list(dict.fromkeys(valid_ips))

    # Enrich all IPs concurrently
    reports: list[IPIntelligenceReport] = []
    async with create_client() as client:
        tasks = [
            enrich_single_web(
                ip, client,
                vt_key=req.keys.virustotal,
                abuse_key=req.keys.abuseipdb,
                shodan_key=req.keys.shodan,
            )
            for ip in valid_ips
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, IPIntelligenceReport):
                reports.append(r)

    # Sort by score descending
    reports.sort(key=lambda r: r.risk.score, reverse=True)

    return {
        "reports": [r.model_dump(mode="json") for r in reports],
        "invalid_ips": invalid_ips,
        "total": len(reports),
    }


@app.post("/api/analyze/stream")
async def analyze_stream(req: AnalyzeRequest):
    """Analyze IPs and stream results via Server-Sent Events."""
    from sse_starlette.sse import EventSourceResponse

    # Validate IPs
    valid_ips = []
    invalid_ips = []
    for raw in req.ips:
        normalized = _validate_ip(raw)
        if normalized:
            valid_ips.append(normalized)
        else:
            invalid_ips.append(raw)

    if not valid_ips:
        return JSONResponse(
            status_code=400,
            content={"error": "No valid IP addresses provided", "invalid": invalid_ips},
        )

    valid_ips = list(dict.fromkeys(valid_ips))

    async def event_generator():
        # Send initial metadata
        yield {
            "event": "init",
            "data": json.dumps({
                "total": len(valid_ips),
                "invalid_ips": invalid_ips,
            }),
        }

        async with create_client() as client:
            tasks = {
                asyncio.create_task(
                    enrich_single_web(
                        ip, client,
                        vt_key=req.keys.virustotal,
                        abuse_key=req.keys.abuseipdb,
                        shodan_key=req.keys.shodan,
                    )
                ): ip
                for ip in valid_ips
            }

            completed = 0
            for coro in asyncio.as_completed(tasks.keys()):
                try:
                    report = await coro
                    completed += 1
                    yield {
                        "event": "result",
                        "data": json.dumps({
                            "report": report.model_dump(mode="json"),
                            "progress": completed,
                            "total": len(valid_ips),
                        }, default=str),
                    }
                except Exception as e:
                    completed += 1
                    yield {
                        "event": "error",
                        "data": json.dumps({
                            "error": str(e),
                            "progress": completed,
                            "total": len(valid_ips),
                        }),
                    }

        # Done
        yield {
            "event": "done",
            "data": json.dumps({"total": len(valid_ips)}),
        }

    return EventSourceResponse(event_generator())


# ── Serve static files (for local dev) ────────────────────────────────────────

_public_dir = Path(__file__).resolve().parent.parent / "public"
if _public_dir.exists():
    @app.get("/", response_class=HTMLResponse)
    async def serve_index():
        return (_public_dir / "index.html").read_text(encoding="utf-8")

    app.mount("/", StaticFiles(directory=str(_public_dir)), name="static")
