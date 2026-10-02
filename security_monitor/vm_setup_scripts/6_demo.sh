#!/bin/bash
# ============================================================
#  Step 6: ONE-COMMAND LIVE DEMO
#
#  What it does:
#    1. starts the monitor with the web dashboard (GUI)
#    2. starts a fake attacker in the background that keeps trying
#       new source IPs, so the dashboard always has something to show
#
#  Nothing here is real: no internet, no email, no Telegram, and it
#  writes to a demo log file inside the project – so it is safe to run
#  anywhere, including on a machine with no SSH server installed.
#
#  Usage:   bash vm_setup_scripts/6_demo.sh
#           PYTHON=/path/to/python bash vm_setup_scripts/6_demo.sh
#  Then open http://localhost:8080
# ============================================================
set -e

cd "$(dirname "$0")/.."                       # always run from security_monitor/
PYTHON="${PYTHON:-python3}"
CONFIG="config/settings_demo.yaml"
DEMO_LOG="logs/demo_auth.log"

mkdir -p logs
: > "$DEMO_LOG"                               # start each demo with a clean log

echo "=============================================================="
echo " Lightweight Security Log Monitor – live demo"
echo "=============================================================="
echo "[*] Config    : $CONFIG"
echo "[*] Watching  : $DEMO_LOG (fed by a fake attacker)"
echo "[*] Web GUI   : http://localhost:8080"
echo "[*] Rule      : 5 failed logins from one IP within 180s → alert"
echo "[*] Alerts    : printed here + appended to logs/alerts.jsonl"
echo "[*] Stop with : Ctrl+C"
echo "=============================================================="
echo ""

# background fake attacker – a new source IP every round
"$PYTHON" -u tests/simulate_attack.py \
    --log "$DEMO_LOG" --loop --delay 2 --count 7 &
ATTACKER=$!
trap 'kill $ATTACKER 2>/dev/null || true' EXIT INT TERM

# foreground monitor + web dashboard
"$PYTHON" -u monitor.py --os linux --config "$CONFIG" --gui
