#!/bin/bash
# ============================================================
#  Step 2: Enable SSH so we can test brute-force attacks
#  Run this INSIDE your Ubuntu VM
# ============================================================
set -e

echo "[*] Installing OpenSSH server..."
sudo apt install -y openssh-server

echo "[*] Starting SSH service..."
sudo systemctl start ssh || sudo systemctl start sshd
sudo systemctl enable ssh 2>/dev/null || sudo systemctl enable sshd

echo "[*] Checking SSH status..."
(sudo systemctl status ssh || sudo systemctl status sshd) | grep "Active:" || true

echo "[*] Your VM's IP address is:"
hostname -I

echo "[*] Looking for the authentication log file..."
if [ -f /var/log/auth.log ]; then
    echo "    [✓] /var/log/auth.log exists  (Debian/Ubuntu)"
    echo "        → keep  log_file: /var/log/auth.log  in settings.yaml"
elif [ -f /var/log/secure ]; then
    echo "    [✓] /var/log/secure exists    (CentOS/RHEL)"
    echo "        → set  log_file: /var/log/secure  in settings.yaml"
else
    echo "    [!] No auth log file found. Two options:"
    echo "        1. sudo apt install -y rsyslog && sudo systemctl restart rsyslog"
    echo "        2. Watch the journal instead:"
    echo "             sudo journalctl -f _COMM=sshd"
fi

echo ""
echo "[✓] SSH is running. Use this IP in your attack simulation."
echo "    Default SSH port: 22"
echo "    Note: Ubuntu's default 'PermitRootLogin prohibit-password' still logs"
echo "          'Failed password for root' for a password attempt, so the demo"
echo "          works without changing sshd_config."
