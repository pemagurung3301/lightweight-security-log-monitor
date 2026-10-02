#!/bin/bash
# ============================================================
#  Step 1: Install Python & dependencies on the Linux VM
#  Run this INSIDE your Ubuntu VM after logging in
# ============================================================
echo "[*] Updating package list..."
sudo apt update -y

echo "[*] Installing Python3 and pip..."
sudo apt install -y python3 python3-pip

echo "[*] Installing PyYAML..."
pip3 install pyyaml

echo "[*] Verifying installation..."
python3 --version
pip3 show pyyaml

echo ""
echo "[✓] All dependencies installed successfully!"
