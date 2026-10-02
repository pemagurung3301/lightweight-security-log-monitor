#!/bin/bash
# ============================================================
#  Step 3: Start the Security Monitor on the Linux VM
#  Run this INSIDE your Ubuntu VM from the project folder
# ============================================================

# Make sure we are in the right folder
if [ ! -f "monitor.py" ]; then
    echo "[ERROR] monitor.py not found."
    echo "  Make sure you are inside the security_monitor/ folder."
    echo "  Run: cd security_monitor"
    exit 1
fi

echo "[*] Starting Lightweight Security Monitor..."
echo "[*] Watching: /var/log/auth.log"
echo "[*] Press Ctrl+C to stop."
echo ""

sudo python3 monitor.py --os linux
