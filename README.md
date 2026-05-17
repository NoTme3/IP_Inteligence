# 🛡 IP Intelligence & Malicious Detection Tool

A Python-based CLI tool that enriches IP addresses with ownership, exposure, and threat intelligence data, then computes a risk score (0–100) with explainable evidence.

## Features

- **Multi-source intelligence** — RDAP, reverse DNS, VirusTotal, AbuseIPDB, Shodan
- **Risk scoring (0–100)** — Weighted signals with explainability
- **Async pipeline** — Concurrent enrichment with per-API rate limiting
- **Multiple output formats** — JSON, CSV, styled HTML reports
- **SQLite persistence** — Query historical results
- **Graceful degradation** — Works with zero, one, or all API keys (fallback to Shodan InternetDB)

## Quick Start

### 1. Setup

```bash
cd ip_intel

# Create virtual environment (required on Kali/Debian)
python3 -m venv venv
venv/bin/pip install -r requirements.txt

# Configure API keys
cp .env.example .env
# Edit .env with your keys
```

### 2. Get API Keys (Free Tiers)

| Service | Rate Limit | Get Key |
|---------|-----------|---------|
| [VirusTotal](https://www.virustotal.com/gui/my-apikey) | 4 req/min, 500/day | Free account |
| [AbuseIPDB](https://www.abuseipdb.com/account/api) | 1,000 req/day | Free account |
| [Shodan](https://account.shodan.io) | 1 req/sec | Paid membership (Free fallback to InternetDB) |

### 3. Run

```bash
# Analyze single IP
./run.sh analyze 8.8.8.8

# Multiple IPs
./run.sh analyze 8.8.8.8 1.1.1.1 9.9.9.9

# From file
./run.sh analyze --file ips.txt

# HTML report
./run.sh analyze 8.8.8.8 1.1.1.1 --output html --save report.html

# CSV output
./run.sh analyze 8.8.8.8 --output csv --save results.csv

# With debug logging
./run.sh analyze 8.8.8.8 -v

# Skip database storage
./run.sh analyze 8.8.8.8 --no-store
```

### 4. Query Stored Results

```bash
# Look up a specific IP
./run.sh query --ip 8.8.8.8

# List all malicious IPs
./run.sh query --classification Malicious

# Show all stored records
./run.sh query --all
```

## Risk Scoring

### Signals

| Signal | Condition | Weight |
|--------|-----------|--------|
| VirusTotal Malicious | Vendor detections > 0 | +3 per vendor (max +25) |
| VirusTotal Suspicious | Suspicious flags > 0 | +2 per vendor (max +10) |
| VirusTotal Reputation | Score < -5 | +abs(score) (max +10) |
| AbuseIPDB High | Confidence > 70% | +20 |
| AbuseIPDB Moderate | Confidence 40–70% | +10 |
| AbuseIPDB Reports | > 50 reports | +10 |
| AbuseIPDB Reports | > 10 reports | +5 |
| Suspicious Hosting | ASN keyword match | +5 |
| Unknown Network | No ASN/org found | +5 |
| AbuseIPDB Whitelisted | Known benign | -15 |
| Suspicious Exposed Ports | Ports like 3389, 445, 1433 exposed | +3 per port (max +10) |
| Known Vulnerabilities | CVEs detected via Shodan | +3 per CVE (max +15) |
| Known Cloud Provider | AWS, GCP, Cloudflare, etc. | -5 |

### Classification

| Score | Label |
|-------|-------|
| 0–20 | ✅ Benign |
| 21–50 | ⚠️ Suspicious |
| 51–75 | 🔶 Likely Malicious |
| 76–100 | 🔴 Malicious |

## Project Structure

```
ip_intel/
├── cli.py                   # Typer CLI
├── config.py                # Settings (.env)
├── models.py                # Pydantic data models
├── core/
│   ├── input_handler.py     # IP parsing & validation
│   └── pipeline.py          # Orchestrator
├── enrichment/
│   ├── rdap.py              # RDAP via ipwhois
│   └── dns.py               # Reverse DNS (PTR)
├── threat_intel/
│   ├── virustotal.py        # VirusTotal API v3
│   ├── abuseipdb.py         # AbuseIPDB API v2
│   └── shodan.py            # Shodan API / InternetDB
├── scoring/
│   └── engine.py            # Risk scoring engine
├── storage/
│   └── database.py          # SQLite persistence
├── reporting/
│   └── renderer.py          # JSON/CSV/HTML output
├── templates/
│   └── report.html          # Jinja2 HTML template
├── run.sh                   # Convenience runner
├── .env.example             # API key template
└── requirements.txt         # Python dependencies
```

## Tech Stack

- **Python 3.10+** with `asyncio`
- **httpx** — Async HTTP client
- **pydantic** — Data validation & models
- **ipwhois** — RDAP/WHOIS lookups
- **aiolimiter** — Per-API rate limiting
- **aiosqlite** — Async SQLite
- **typer + rich** — CLI & console output
- **jinja2** — HTML report templating

## License

MIT
