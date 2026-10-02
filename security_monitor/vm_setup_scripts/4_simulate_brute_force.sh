#!/bin/bash
# ============================================================
#  Step 4: Simulate a brute-force SSH attack
#  Run this from your HOST machine (NOT inside the VM)
#  This uses the 'hydra' tool to hammer SSH with wrong passwords
#
#  Install hydra on host:  sudo apt install hydra  (Linux)
#                          brew install hydra       (Mac)
#
#  Usage: bash 4_simulate_brute_force.sh <VM_IP_ADDRESS> [username]
# ============================================================

VM_IP=$1
USERNAME=${2:-root}

if [ -z "$VM_IP" ]; then
    echo "Usage: bash 4_simulate_brute_force.sh <VM_IP> [username]"
    echo "Example: bash 4_simulate_brute_force.sh 192.168.1.105"
    exit 1
fi

if ! command -v hydra >/dev/null 2>&1; then
    echo "[ERROR] hydra is not installed on this machine."
    echo "  Linux: sudo apt install hydra      Mac: brew install hydra"
    echo ""
    echo "  No hydra? You can run the attack from inside the VM instead:"
    echo "     python3 tests/simulate_attack.py"
    exit 1
fi

echo "[*] Starting SSH brute-force simulation against $VM_IP as '$USERNAME'"
echo "[*] This will generate 10 failed login attempts..."
echo ""

# -l  = username to try
# -P  = password list file (we generate a fake one)
# -t 1 = one task at a time, so the attempts arrive in a neat order
# -V  = verbose (show each attempt)

# Create a small fake password list
echo -e "wrong1\nwrong2\nwrong3\nwrong4\nwrong5\nwrong6\nwrong7\nwrong8\nwrong9\nwrong10" \
    > /tmp/fake_passwords.txt

hydra -l "$USERNAME" -P /tmp/fake_passwords.txt -t 1 -V "ssh://$VM_IP"

echo ""
echo "[*] Attack simulation complete. Check the monitor terminal for alerts!"

# Cleanup
rm -f /tmp/fake_passwords.txt
