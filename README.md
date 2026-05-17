# 🛡 IP Intelligence — Analyst-Grade Threat Analysis

A modern, fast, and highly accurate IP intelligence platform that goes beyond simple additive scoring. It enriches IPs across 5 major threat feeds and provides an **Evidence-Aware Risk Score**, separating direct malicious activity from infrastructure attribution confidence.

It features both a rich Terminal CLI and a stunning Glassmorphic Web Dashboard.

## 🌟 Key Features

- **Multi-Source Intelligence:** VirusTotal, AbuseIPDB, Shodan (or InternetDB), GreyNoise, and AlienVault OTX.
- **Evidence-Aware Scoring:** Differentiates between *Direct Malicious Evidence* (e.g. malware C2) and *Contextual Associations* (e.g. community pulses).
- **Attribution Confidence:** Classifies infrastructure (Cloud, CDN, VPS, Residential, Enterprise) to adjust confidence. A malicious IP on Cloudflare reduces attribution confidence, but doesn't blindly erase the threat score.
- **Contradiction Detection:** Alerts analysts when feeds contradict each other (e.g. GreyNoise says Benign Service, but VirusTotal says Malicious).
- **Explainable AI (Analyst Reasoning):** Provides plain-English justification for *why* an IP received its score.
- **Modern Web UI:** Fast, responsive, glassmorphism design with real-time Server-Sent Events (SSE) streaming and detailed visual confidence graphs.
- **Built-in Security:** In-memory rate limiting and restricted CORS for the web API.

## 🚀 Quick Start

### 1. Setup

```bash
git clone https://github.com/NoTme3/IP_Inteligence.git
cd IP_Inteligence

# Create virtual environment 
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configure API keys
cp .env.example .env
# Edit .env with your keys
```

### 2. Run the Web Dashboard (Recommended)

```bash
# Start the FastAPI server
./venv/bin/uvicorn app:app --host 0.0.0.0 --port 8000
```
Then open `http://localhost:8000` in your browser.

### 3. Run the CLI

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
2. **Signal Categorization:** Evidence is binned into `Direct Malicious`, `Contextual`, and `Reputation`. Each category has contribution caps to prevent score inflation (e.g., you can't get a 100/100 just from 20 low-confidence OTX pulses).
3. **Corroboration:** If multiple independent feeds agree, the score is multiplied (boosted). If one feed says Malicious but 3 say Benign, the signal is dampened.
4. **Data Completeness:** If feeds are rate-limited or down, the engine tracks completeness. Below 40%, it safely defaults to `Insufficient Data` rather than returning a false-negative `Benign`.

## 🛠 Tech Stack

- **Backend:** Python 3.10+, FastAPI, Pydantic, HTTPX (Async), SQLite (Aiosqlite)
- **Frontend:** Vanilla JS, CSS (Glassmorphism), Server-Sent Events (SSE)
- **CLI:** Typer, Rich

## 📝 License

All Rights Reserved.
