"""
simulate_attack.py
──────────────────
TEST SCRIPT – Simulates a brute-force SSH attack by writing
fake failed login lines directly into a test log file.

Use this to test your monitor WITHOUT needing a real attack.

HOW TO USE:
  Step 1: In terminal 1, start the monitor in test mode:
          python3 monitor.py --os linux
          (and change log_file in settings.yaml to 'logs/test_auth.log')

  Step 2: In terminal 2, run this script:
          python3 tests/simulate_attack.py

  Step 3: Watch terminal 1 – you should see the alert fire!
"""

import time
import os

# Where to write fake log lines
TEST_LOG_FILE = "logs/test_auth.log"

# The fake attacker's IP address
ATTACKER_IP = "10.0.0.99"

# How many fake failures to generate
NUM_FAILURES = 8

# Delay between each fake failure (seconds)
DELAY_BETWEEN = 5


def simulate_brute_force():
    """Write fake failed SSH login lines to the test log file."""

    # Make sure the logs folder exists
    os.makedirs("logs", exist_ok=True)

    print(f"[*] Starting brute-force simulation")
    print(f"[*] Writing {NUM_FAILURES} fake failures to: {TEST_LOG_FILE}")
    print(f"[*] Attacker IP: {ATTACKER_IP}")
    print()

    for i in range(1, NUM_FAILURES + 1):
        # Build a fake log line that looks like a real auth.log entry
        from datetime import datetime
        timestamp = datetime.now().strftime("%b %d %H:%M:%S")
        hostname  = "testserver"
        username  = "root"

        # This is exactly what Linux writes when an SSH login fails
        log_line = (
            f"{timestamp} {hostname} sshd[9999]: "
            f"Failed password for {username} from {ATTACKER_IP} port 22 ssh2\n"
        )

        # Append to the log file
        with open(TEST_LOG_FILE, "a") as f:
            f.write(log_line)

        print(f"  [{i}/{NUM_FAILURES}] Written: {log_line.strip()}")
        time.sleep(DELAY_BETWEEN)

    print(f"\n[*] Simulation complete. Check if your monitor sent an alert!")


if __name__ == "__main__":
    simulate_brute_force()
