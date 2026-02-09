#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== EDR PoC Setup ==="

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "[+] Creating virtual environment..."
    python3 -m venv venv
fi

echo "[+] Activating virtual environment..."
source venv/bin/activate

echo "[+] Installing dependencies..."
pip install -r requirements.txt

# Create data directories
mkdir -p data/models data/quarantine

echo "[+] Starting EDR..."
python3 run_edr.py "$@"
