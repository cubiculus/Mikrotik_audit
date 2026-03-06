#!/bin/bash
# Quick run script for MikroTik Audit Tool (Linux/Mac)
# Usage: ./scripts/run_audit.sh --ssh-user admin --ssh-pass your_password

if [ ! -d "venv" ]; then
    echo "[ERROR] Virtual environment not found!"
    echo "Run: bash scripts/install.sh"
    exit 1
fi

source venv/bin/activate
python -m src.cli "$@"
