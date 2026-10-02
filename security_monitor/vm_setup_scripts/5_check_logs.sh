#!/bin/bash
# ============================================================
#  Step 5: Manually check the auth.log to see what was recorded
#  Run this INSIDE your Ubuntu VM
#
#  Usage:  bash 5_check_logs.sh            → only the interesting lines
#          bash 5_check_logs.sh --all      → the last 30 lines, unfiltered
# ============================================================

LOG_FILE=/var/log/auth.log
[ -f "$LOG_FILE" ] || LOG_FILE=/var/log/secure

if [ ! -f "$LOG_FILE" ]; then
    echo "[ERROR] No auth log found (/var/log/auth.log or /var/log/secure)."
    echo "  Try: sudo journalctl -f _COMM=sshd"
    exit 1
fi

if [ "$1" == "--all" ]; then
    echo "[*] Last 30 lines of $LOG_FILE:"
    sudo tail -30 "$LOG_FILE"
    exit 0
fi

echo "[*] Last 200 lines of $LOG_FILE, filtered:"
echo "    (Look for 'Failed password' lines – those are the ones we count)"
echo "============================================"
# NOTE: the old version of this line ended with "...|error|$". The trailing
# "|$" matches every line, so the filter did not filter anything at all.
sudo tail -200 "$LOG_FILE" | grep --color=always -E "Failed password|Invalid user|Accepted|maximum authentication attempts" \
    || echo "    (nothing matched yet – run 4_simulate_brute_force.sh)"

echo ""
echo "[*] Failures per source IP:"
sudo tail -2000 "$LOG_FILE" | grep -oE "Failed password for (invalid user )?[a-zA-Z0-9._-]+ from [0-9A-Fa-f:.]+" \
    | grep -oE "[0-9A-Fa-f:.]+$" | sort | uniq -c | sort -rn | head -10 \
    || echo "    (none yet)"
