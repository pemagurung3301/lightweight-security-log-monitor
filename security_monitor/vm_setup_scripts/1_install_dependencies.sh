#!/bin/bash
# ============================================================
#  Step 1: Install Python & dependencies on the Linux VM
#  Run this INSIDE your Ubuntu VM after logging in
# ============================================================
set -e

echo "[*] Updating package list..."
sudo apt update

echo "[*] Installing Python3 and pip..."
sudo apt install -y python3 python3-pip

# Ubuntu 23.04 and newer refuse "pip3 install <package>" outside a virtual
# environment (PEP 668: "externally-managed-environment"). Installing the
# distro package avoids that problem entirely and needs no venv.
echo "[*] Installing PyYAML (the system package – works on new and old Ubuntu)..."
if sudo apt install -y python3-yaml; then
    :
else
    echo "[!] apt package unavailable, falling back to pip..."
    pip3 install pyyaml || pip3 install --user pyyaml || \
        pip3 install --break-system-packages pyyaml
fi

echo "[*] Verifying installation..."
python3 --version
python3 -c "import yaml; print('pyyaml', yaml.__version__, 'OK')"

echo ""
echo "[✓] All dependencies installed successfully!"
