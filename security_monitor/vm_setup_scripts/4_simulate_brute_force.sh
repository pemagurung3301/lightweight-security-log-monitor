#!/bin/bash
# ============================================================
#  Step 4: Simulate a brute-force SSH attack
#  Run this from your HOST machine (NOT inside the VM)
#  This uses the 'hydra' tool to hammer SSH with wrong passwords
#
#  Install hydra on host:  sudo apt install hydra  (Linux)
#                          brew install hydra       (Mac)
#
#  Usage: bash 4_simulate_brute_force.sh <VM_IP_ADDRESS>
# ============================================================

VM_IP=$1

if [ -z "$VM_IP" ]; then
    echo "Usage: bash 4_simulate_brute_force.sh <VM_IP>"
    echo "Example: bash 4_simulate_brute_force.sh 192.168.1.105"
    exit 1
fi

echo "[*] Starting SSH brute-force simulation against $VM_IP"
echo "[*] This will generate 10 failed login attempts..."
echo ""

# Try 10 wrong passwords for the 'root' user
# -l  = username to try
# -P  = password list file (we generate a fake one)
# -t  = number of parallel tasks
# -V  = verbose (show each attempt)

# Create a small fake password list
echo -e "wrong1\nwrong2\nwrong3\nwrong4\nwrong5\nwrong6\nwrong7\nwrong8\nwrong9\nwrong10" > /tmp/fake_passwords.txt

hydra -l root -P /tmp/fake_passwords.txt -t 1 -V ssh://$VM_IP

echo ""
echo "[*] Attack simulation complete. Check the monitor terminal for alerts!"

# Cleanup
rm /tmp/fake_passwords.txt
