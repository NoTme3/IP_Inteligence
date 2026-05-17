#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# ip-intel — convenience wrapper
#
# Usage:
#   ./run.sh analyze 8.8.8.8
#   ./run.sh analyze --file ips.txt --output html
#   ./run.sh query --all
# ──────────────────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PYTHON="${SCRIPT_DIR}/venv/bin/python"

if [ ! -f "$VENV_PYTHON" ]; then
    echo "❌  Virtual environment not found. Run:"
    echo "    python3 -m venv ${SCRIPT_DIR}/venv"
    echo "    ${SCRIPT_DIR}/venv/bin/pip install -r ${SCRIPT_DIR}/requirements.txt"
    exit 1
fi

export PYTHONPATH="$(dirname "$SCRIPT_DIR")"
exec "$VENV_PYTHON" -m ip_intel "$@"
