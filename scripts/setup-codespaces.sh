#!/bin/bash
set -euo pipefail

echo "============================================"
echo "  Harvesto Scanner — Codespaces Setup"
echo "============================================"

# System deps
echo "[1/6] Installing system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y -qq python3 python3-pip python3-venv nodejs npm jq curl git > /dev/null 2>&1

# Python venv
echo "[2/6] Creating Python virtual environment..."
python3 -m venv .venv
source .venv/bin/activate

# Python deps
echo "[3/6] Installing Python dependencies..."
pip install --quiet \
    slither-analyzer \
    solc-select \
    crytic-compile \
    pyyaml \
    rich \
    click \
    dataclasses-json

# Install solc
echo "[4/6] Installing Solidity compiler..."
solc-select install 0.8.20
solc-select install 0.8.24
solc-select install 0.8.26
solc-select use 0.8.20

# Install Foundry
echo "[5/6] Installing Foundry (forge, cast, anvil)..."
if ! command -v forge &> /dev/null; then
    curl -L https://foundry.paradigm.xyz | bash
    source ~/.bashrc 2>/dev/null || true
    ~/.foundry/bin/foundryup
fi

# Install the scanner as editable package
echo "[6/6] Installing Harvesto Scanner..."
pip install --quiet -e .

# Create convenience alias
echo 'alias harvesto="python -m harvesto_scanner"' >> ~/.bashrc

echo ""
echo "============================================"
echo "  Setup complete!"
echo ""
echo "  Usage:"
echo "    source .venv/bin/activate"
echo "    harvesto scan ./contracts/"
echo "    harvesto scan ./contracts/ --format markdown"
echo "    harvesto bench ./benchmarks/ --output audit.md"
echo "============================================"
