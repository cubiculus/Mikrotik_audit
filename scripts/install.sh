#!/bin/bash
# Quick installation script for MikroTik Audit Tool (Linux/Mac)
# Run: bash scripts/install.sh

set -e

echo "========================================"
echo "MikroTik Audit Tool - Quick Install"
echo "========================================"
echo

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 is not installed"
    echo "Please install Python 3.9+ first"
    exit 1
fi

echo "[1/4] Python found: $(python3 --version)"
echo

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "[2/4] Creating virtual environment..."
    python3 -m venv venv
else
    echo "[2/4] Virtual environment already exists"
fi
echo

# Activate and install dependencies
echo "[3/4] Installing dependencies..."
source venv/bin/activate
pip install --upgrade pip > /dev/null
pip install -r requirements.txt
echo

# Create reports directory
if [ ! -d "audit-reports" ]; then
    echo "[4/4] Creating reports directory..."
    mkdir -p audit-reports
else
    echo "[4/4] Reports directory already exists"
fi
echo

echo "========================================"
echo "Installation complete!"
echo
echo To run the audit tool:
echo "  source venv/bin/activate"
echo "  python -m src.cli --ssh-user admin --ssh-pass your_password"
echo
echo Or use the quick command:
echo "  ./scripts/run_audit.sh --ssh-user admin --ssh-pass your_password"
echo "========================================
