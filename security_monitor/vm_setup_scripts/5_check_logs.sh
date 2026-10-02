#!/bin/bash
# ============================================================
#  Step 5: Manually check the auth.log to see what was recorded
#  Run this INSIDE your Ubuntu VM
# ============================================================
echo "[*] Last 30 lines of /var/log/auth.log:"
echo "    (Look for 'Failed password' lines)"
echo "============================================"
sudo tail -30 /var/log/auth.log | grep --color=always -E "Failed|Invalid|Accepted|error|$"
