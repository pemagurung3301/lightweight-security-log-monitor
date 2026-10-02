"""
simulate_attack.py
──────────────────
TEST SCRIPT – Simulates a brute-force SSH attack by writing fake failed
login lines into the log file the monitor is watching.

Use this to test your monitor WITHOUT needing a real attack. It writes the
exact line format OpenSSH produces, so the monitor cannot tell the difference.

HOW TO USE
  Step 1: point config/settings.yaml at the demo log file:
              linux:
                log_file: logs/test_auth.log
  Step 2: in terminal 1, start the monitor:
              python3 monitor.py --os linux
  Step 3: in terminal 2, run this script:
              python3 tests/simulate_attack.py
  Step 4: watch terminal 1 – the alert fires on the 5th failure.

The script reads log_file from your settings.yaml, so it can never write to a
different file than the one being monitored. Override anything you like:

    python3 tests/simulate_attack.py --count 12 --delay 1 --ip 203.0.113.7

For a live dashboard demo, keep the attacks coming from new IPs forever:

    python3 monitor.py --os linux --gui
    python3 tests/simulate_attack.py --loop --delay 2
"""

import argparse
import os
import random
import sys
import time
from datetime import datetime

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)                     # the security_monitor folder
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from modules.config_loader import load_config      # noqa: E402


def parse_args():
    p = argparse.ArgumentParser(description="Write fake SSH brute-force lines into a log file")
    p.add_argument("--config", default=None, help="path to settings.yaml")
    p.add_argument("--log", default=None,
                   help="log file to write to (default: linux.log_file from settings.yaml)")
    p.add_argument("--ip", default="10.0.0.99", help="fake attacker IP")
    p.add_argument("--count", type=int, default=8, help="how many failures to write")
    p.add_argument("--delay", type=float, default=5.0, help="seconds between failures")
    p.add_argument("--users", default="root,admin,oracle,test",
                   help="comma-separated usernames the 'attacker' tries")
    p.add_argument("--loop", action="store_true",
                   help="keep attacking forever with a new random IP every round "
                        "(nice for a live dashboard demo – Ctrl+C to stop)")
    p.add_argument("--rounds", type=int, default=0, help="stop after N rounds (0 = forever)")
    return p.parse_args()


def build_line(ts: str, username: str, ip: str, pid: int = 9999,
               hostname: str = "testserver") -> str:
    """Return a line in exactly the format OpenSSH writes to auth.log."""
    return (f"{ts} {hostname} sshd[{pid}]: "
            f"Failed password for {username} from {ip} port 22 ssh2\n")


def simulate_brute_force(log_file: str, ip: str, count: int, delay: float, users: list):
    folder = os.path.dirname(os.path.abspath(log_file))
    if folder:
        os.makedirs(folder, exist_ok=True)

    print("[*] Starting brute-force simulation")
    print(f"[*] Writing {count} fake failures to: {log_file}")
    print(f"[*] Attacker IP: {ip}   usernames: {', '.join(users)}")
    print(f"[*] One failure every {delay}s\n")

    for i in range(1, count + 1):
        username = users[(i - 1) % len(users)]
        line = build_line(datetime.now().strftime("%b %d %H:%M:%S"), username, ip)
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(line)
            f.flush()
        print(f"  [{i}/{count}] {line.strip()}")
        if i < count:
            time.sleep(delay)

    print("\n[*] Simulation complete. Check the monitor terminal for the alert.")


def random_attacker_ip() -> str:
    """A random-looking public IP for the loop demo (documentation range)."""
    return f"203.0.{random.randint(113, 200)}.{random.randint(2, 250)}"


def main():
    args = parse_args()
    log_file = args.log
    if not log_file:
        config = load_config(args.config)
        log_file = config["linux"]["log_file"]
        if not os.path.isabs(log_file):
            log_file = os.path.join(_ROOT, log_file)

    users = [u.strip() for u in args.users.split(",") if u.strip()]

    if not args.loop:
        simulate_brute_force(log_file, args.ip, args.count, args.delay, users)
        return

    round_no = 0
    try:
        while True:
            round_no += 1
            ip = args.ip if args.ip != "10.0.0.99" else random_attacker_ip()
            print(f"\n{'=' * 60}\n[*] Round {round_no}: attacker {ip}\n{'=' * 60}")
            simulate_brute_force(log_file, ip, args.count, args.delay, users)
            if args.rounds and round_no >= args.rounds:
                print(f"\n[*] {args.rounds} rounds done.")
                break
            print("[*] Waiting 20s before the next attacker… (Ctrl+C to stop)")
            time.sleep(20)
    except KeyboardInterrupt:
        print("\n[*] Simulation stopped.")


if __name__ == "__main__":
    main()
