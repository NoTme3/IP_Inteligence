"""Run the web interface locally with uvicorn.

Usage:
    cd ip_intel/web
    pip install -r requirements.txt
    python serve_local.py
    # Open http://localhost:8000
"""

import sys
from pathlib import Path

# Ensure the project root is on the Python path so `ip_intel` is importable
project_root = Path(__file__).resolve().parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

import uvicorn
from api.index import app

if __name__ == "__main__":
    print("\n🛡  IP Intelligence — Web Interface")
    print("    http://localhost:8000\n")
    uvicorn.run(app, host="0.0.0.0", port=8000)
