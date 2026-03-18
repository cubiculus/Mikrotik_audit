#!/bin/bash
# One-line installation script for MikroTik Audit Tool
# Usage: bash <(curl -Ls https://raw.githubusercontent.com/cubiculus/Mikrotik_audit/main/scripts/quick_install.sh)
# Or: curl -Ls https://raw.githubusercontent.com/cubiculus/Mikrotik_audit/main/scripts/quick_install.sh | bash

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "========================================"
echo -e "${GREEN}MikroTik Audit Tool - Quick Install${NC}"
echo "========================================"
echo

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[ERROR] Python 3 is not installed${NC}"
    echo "Please install Python 3.9+ first:"
    echo "  Ubuntu/Debian: sudo apt install python3 python3-pip python3-venv"
    echo "  CentOS/RHEL:   sudo yum install python3 python3-pip python3-virtualenv"
    echo "  macOS:         brew install python3"
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1,2)
echo -e "${GREEN}[1/5]${NC} Python found: $(python3 --version)"

# Check Python version (must be 3.9+)
REQUIRED_VERSION="3.9"
if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo -e "${RED}[ERROR] Python 3.9+ is required (found: $PYTHON_VERSION)${NC}"
    exit 1
fi

# Clone repository
REPO_URL="https://github.com/cubiculus/Mikrotik_audit.git"
TEMP_DIR=$(mktemp -d)

echo -e "${GREEN}[2/5]${NC} Cloning repository..."
git clone "$REPO_URL" "$TEMP_DIR" --depth 1 2>/dev/null || {
    echo -e "${RED}[ERROR] Failed to clone repository. Make sure git is installed.${NC}"
    exit 1
}

cd "$TEMP_DIR"

# Create virtual environment
echo -e "${GREEN}[3/5]${NC} Creating virtual environment..."
python3 -m venv venv

# Activate and install dependencies
echo -e "${GREEN}[4/5]${NC} Installing dependencies..."
source venv/bin/activate
pip install --upgrade pip > /dev/null 2>&1
pip install -r requirements.txt > /dev/null 2>&1

# Create reports directory
echo -e "${GREEN}[5/5]${NC} Creating reports directory..."
mkdir -p audit-reports

# Move to user's home or current directory
INSTALL_DIR="$HOME/mikrotik-audit"
if [ -d "$INSTALL_DIR" ]; then
    INSTALL_DIR="$HOME/mikrotik-audit-$(date +%Y%m%d-%H%M%S)"
fi

mv "$TEMP_DIR" "$INSTALL_DIR"

echo
echo "========================================"
echo -e "${GREEN}Installation complete!${NC}"
echo "========================================"
echo
echo "Installation directory: ${YELLOW}$INSTALL_DIR${NC}"
echo
echo "To run the audit tool:"
echo "  1. Configure credentials in .env file:"
echo "     cd $INSTALL_DIR"
echo "     cp .env.example .env"
echo "     # Edit .env with your settings"
echo "  2. Run the audit:"
echo "     cd $INSTALL_DIR"
echo "     source venv/bin/activate"
echo "     python -m src.cli --ssh-user admin"
echo "     # Password will be prompted interactively"
echo
echo "Or use the quick command:"
echo "  $INSTALL_DIR/scripts/run_audit.sh --ssh-user admin"
echo
echo -e "For more information: ${YELLOW}https://github.com/cubiculus/Mikrotik_audit${NC}"
echo "========================================"
