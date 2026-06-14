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
from collections import defaultdict

# ── Internal Modules ──────────────────────────────────────────────────────────
from core.pipeline import enrich_single_web
from models import IPIntelligenceReport
from utils.http_client import create_client
from utils.rate_tracker import trackers as rate_trackers

# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="IP Intelligence",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000"
    ],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# ── Rate Limiting ─────────────────────────────────────────────────────────────

RATE_LIMIT_DURATION = 60
MAX_REQUESTS_PER_MINUTE = 30
_rate_limits = defaultdict(list)

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    # Only limit API endpoints
    if request.url.path.startswith("/api/"):
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        
        # Clean old requests
        _rate_limits[client_ip] = [t for t in _rate_limits[client_ip] if now - t < RATE_LIMIT_DURATION]
        
        if len(_rate_limits[client_ip]) >= MAX_REQUESTS_PER_MINUTE:
            return JSONResponse(
                status_code=429,
                content={"error": "Rate limit exceeded. Please try again later."}
            )
            
        _rate_limits[client_ip].append(now)
        
    return await call_next(request)

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # Do not leak stack traces to the frontend in production
    return JSONResponse(
        status_code=500,
        content={"error": f"Internal Server Error: {str(exc)}"}
    )

# ── Constants ─────────────────────────────────────────────────────────────────

MAX_IPS_PER_REQUEST = 100


# ── Request / Response Models ─────────────────────────────────────────────────


class APIKeys(BaseModel):
    virustotal: str = ""
    abuseipdb: str = ""
    shodan: str = ""
    greynoise: str = ""
    alienvault: str = ""


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


@app.get("/api/rate-status")
async def rate_status():
    """Return current rate-limit budget status for all providers."""
    return {
        "providers": {
            name: tracker.get_status()
            for name, tracker in rate_trackers.items()
        }
    }


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

    # Enrich all IPs concurrently with a semaphore
    sem = asyncio.Semaphore(5)

    async def _bound_enrich(ip, client):
        async with sem:
            return await enrich_single_web(
                ip, client,
                vt_key=req.keys.virustotal,
                abuse_key=req.keys.abuseipdb,
                shodan_key=req.keys.shodan,
                greynoise_key=req.keys.greynoise,
                alienvault_key=req.keys.alienvault,
            )

    reports: list[IPIntelligenceReport] = []
    async with create_client() as client:
        tasks = [_bound_enrich(ip, client) for ip in valid_ips]
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

        sem = asyncio.Semaphore(5)

        async def _bound_enrich_stream(ip, client):
            async with sem:
                return await enrich_single_web(
                    ip, client,
                    vt_key=req.keys.virustotal,
                    abuse_key=req.keys.abuseipdb,
                    shodan_key=req.keys.shodan,
                    greynoise_key=req.keys.greynoise,
                    alienvault_key=req.keys.alienvault,
                )

        async with create_client() as client:
            tasks = {
                asyncio.create_task(_bound_enrich_stream(ip, client)): ip
                for ip in valid_ips
            }

            completed = 0
            for coro in asyncio.as_completed(tasks.keys()):
                try:
                    # Snapshot tracker state before enrichment
                    pre_waits = {
                        name: t.last_wait_seconds
                        for name, t in rate_trackers.items()
                    }

                    report = await coro
                    completed += 1

                    # Check if any tracker had to wait (budget guard fired)
                    for name, t in rate_trackers.items():
                        if t.last_wait_seconds > 0 and t.last_wait_seconds != pre_waits.get(name, 0):
                            yield {
                                "event": "rate_limit",
                                "data": json.dumps({
                                    "provider": t.provider,
                                    "wait_seconds": round(t.last_wait_seconds, 1),
                                    "message": f"{t.provider} rate limit reached. Waited {t.last_wait_seconds:.0f}s for budget reset.",
                                }),
                            }

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

_public_dir = Path(__file__).resolve().parent / "public"
if _public_dir.exists():
    @app.get("/", response_class=HTMLResponse)
    async def serve_index():
        return (_public_dir / "index.html").read_text(encoding="utf-8")

    # Serve individual known files explicitly so the mount doesn't shadow "/"
    from fastapi.responses import FileResponse

    @app.get("/{filename:path}")
    async def serve_static(filename: str):
        file_path = _public_dir / filename
        if file_path.exists() and file_path.is_file():
            headers = {
                "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                "Pragma": "no-cache",
                "Expires": "0"
            }
            return FileResponse(str(file_path), headers=headers)
        return HTMLResponse(status_code=404, content="Not Found")
