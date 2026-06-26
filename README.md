# 🛡 IP Intelligence — Analyst-Grade Threat Analysis

A modern, fast, and highly accurate IP intelligence platform that goes beyond simple additive scoring. It enriches IPs across 5 major threat feeds and provides an **Evidence-Aware Risk Score**, separating direct malicious activity from infrastructure attribution confidence.

It features both a rich Terminal CLI and a stunning Glassmorphic Web Dashboard.

## 🌟 Key Features

- **Multi-Source Intelligence:** VirusTotal, AbuseIPDB, Shodan (or InternetDB), GreyNoise, AlienVault OTX, and NVD (CVEs).
- **Deep OSINT Enrichment:** 
  - **OpenSanctions / OFAC:** Fuzzy-matching for sanctioned entities and organizations.
  - **TLS/SSL Inspection:** Expiry detection and self-signed certificate flagging.
  - **Country Risk:** Geopolitical risk scoring based on FATF and APT attribution data.
  - **Full DNS Enumeration:** Automated A, AAAA, MX, NS, and TXT record resolution with FCrDNS validation.
- **Evidence-Aware Scoring:** Differentiates between *Direct Malicious Evidence* (e.g. malware C2) and *Contextual Associations* (e.g. community pulses).
- **Attribution Confidence:** Classifies infrastructure (Cloud, CDN, VPS, Residential, Enterprise) to adjust confidence.
- **Explainable AI (Analyst Reasoning):** Provides plain-English justification for *why* an IP received its score.
- **Modern Web UI:** Fast, responsive, glassmorphism design with real-time Server-Sent Events (SSE) streaming and detailed visual confidence graphs.
- **Advanced Threat Map:** Hardware-accelerated WebGL map using **MapLibre GL JS**, featuring CartoDB Dark Matter vector tiles, native GeoJSON point clustering, and smooth `flyTo` camera animations.
- **Pro Workflows:** Full keyboard navigability (use `/` for search, `?` for shortcuts) and data export options (PDF, JSON, CSV).

## 🚀 Quick Start

### Option 1: Docker (Recommended for Production)

```bash
git clone https://github.com/NoTme3/IP_Inteligence.git
cd IP_Inteligence

# Copy the environment file and add your API keys
cp .env.example .env

# Build and run using Docker Compose
docker-compose up -d --build
```
Open `http://localhost:8000` in your browser.

### Option 2: Local Virtual Environment

```bash
git clone https://github.com/NoTme3/IP_Inteligence.git
cd IP_Inteligence

# Create virtual environment 
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configure API keys
cp .env.example .env

# Start the FastAPI server
./venv/bin/uvicorn app:app --host 0.0.0.0 --port 8000
```

### Option 3: Run the CLI

```bash
# Analyze a single IP
./run.sh analyze 8.8.8.8

# Analyze multiple IPs from a file
./run.sh analyze --file ips.txt

# Query historical results from the SQLite database
./run.sh query --classification Malicious
```

## 🧠 How the Scoring Engine Works

The scoring engine has been completely refactored to act like a human analyst:

1. **Infrastructure Classification:** Detects if the IP belongs to a CDN, Shared Cloud, VPS, or Enterprise. This sets the **Attribution Confidence %**.
2. **Signal Categorization:** Evidence is binned into `Direct Malicious`, `Contextual`, and `Reputation`. Each category has contribution caps to prevent score inflation.
3. **OSINT Verification:** Checks for expired TLS certificates, sanctioned ASNs, missing PTR records, and high-risk geographical regions.
4. **Corroboration:** If multiple independent feeds agree, the score is multiplied (boosted). If one feed says Malicious but 3 say Benign, the signal is dampened.

## 🛠 Tech Stack

- **Backend:** Python 3.12+, FastAPI, Pydantic, HTTPX (Async), SQLite (Aiosqlite), dnspython
- **Frontend:** Vanilla JS, CSS (Glassmorphism), Server-Sent Events (SSE), MapLibre GL JS
- **Infrastructure:** Docker, Docker Compose
- **CLI:** Typer, Rich


