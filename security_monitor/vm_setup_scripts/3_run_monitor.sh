#!/bin/bash
# ============================================================
#  Step 3: Start the Security Monitor on the Linux VM
#  Run this INSIDE your Ubuntu VM from the project folder
#
#  Usage:
#     bash 3_run_monitor.sh          → terminal (CLI) mode
#     bash 3_run_monitor.sh --gui    → terminal + web dashboard
# ============================================================

# Make sure we are in the right folder
if [ ! -f "monitor.py" ]; then
    echo "[ERROR] monitor.py not found."
    echo "  Make sure you are inside the security_monitor/ folder."
    echo "  Run: cd security_monitor"
    exit 1
fi

LOG_FILE=$(grep -E "^\s*log_file:" config/settings.yaml | head -1 | sed 's/.*log_file:\s*//')
echo "[*] Starting Lightweight Security Monitor..."
echo "[*] Watching: ${LOG_FILE:-/var/log/auth.log}"

if [ "$1" == "--gui" ]; then
    echo "[*] Web dashboard: http://localhost:8080"
    echo "[*] From another machine on the same network: http://$(hostname -I | awk '{print $1}'):8080"
fi

echo "[*] Press Ctrl+C to stop."
echo ""

# sudo is needed because /var/log/auth.log is only readable by root/adm.
# "-u" keeps Python's output unbuffered so you see alerts immediately.
sudo python3 -u monitor.py --os linux "$@"
