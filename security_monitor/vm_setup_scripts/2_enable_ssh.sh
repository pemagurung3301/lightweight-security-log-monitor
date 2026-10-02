#!/bin/bash
# ============================================================
#  Step 2: Enable SSH so we can test brute-force attacks
#  Run this INSIDE your Ubuntu VM
# ============================================================
echo "[*] Installing OpenSSH server..."
sudo apt install -y openssh-server

echo "[*] Starting SSH service..."
sudo systemctl start ssh
sudo systemctl enable ssh

echo "[*] Checking SSH status..."
sudo systemctl status ssh | grep "Active:"

echo "[*] Your VM's IP address is:"
hostname -I

echo ""
echo "[✓] SSH is running. Use this IP in your attack simulation."
echo "    Default SSH port: 22"
