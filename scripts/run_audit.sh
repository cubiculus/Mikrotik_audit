#!/bin/bash
# Quick run script for MikroTik Audit Tool (Linux/Mac)
# Usage: ./scripts/run_audit.sh --ssh-user admin
# Note: Configure password in .env file or enter interactively

# Change to the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

if [ ! -d "venv" ]; then
    echo "[ERROR] Virtual environment not found!"
    echo "Run: bash scripts/install.sh"
    exit 1
fi

source venv/bin/activate
python -m src.cli "$@"
