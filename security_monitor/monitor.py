"""
===============================================================
  Lightweight Security Log Monitor
  Author : Pema Sherap Gurung (NP070051)
  Purpose: Final Year Project – SME Cybersecurity, Nepal
===============================================================

HOW TO RUN:
  Linux  →  sudo python3 monitor.py --os linux
  Windows→  python monitor.py --os windows
"""

import argparse
import time
import sys
import os

# ── import our own modules ────────────────────────────────────
from modules.linux_parser   import LinuxLogParser
from modules.windows_parser import WindowsLogParser
from modules.threshold_engine import ThresholdEngine
from modules.alerter        import Alerter
from modules.config_loader  import load_config

# ─────────────────────────────────────────────────────────────
def main():
    # 1. Read command-line argument: --os linux  OR  --os windows
    parser = argparse.ArgumentParser(
        description="Lightweight Security Log Monitor for SMEs"
    )
    parser.add_argument(
        "--os",
        choices=["linux", "windows"],
        required=True,
        help="Which operating system are you monitoring?"
    )
    args = parser.parse_args()

    # 2. Load settings from config/settings.yaml
    config = load_config("config/settings.yaml")

    # 3. Set up the alerter (email + telegram)
    alerter = Alerter(config)

    # 4. Set up the threshold engine (detects attacks)
    engine = ThresholdEngine(config)

    # 5. Choose the right log parser based on OS
    if args.os == "linux":
        log_parser = LinuxLogParser(config)
        print("[*] Starting Linux log monitor...")
        print(f"[*] Watching: {config['linux']['log_file']}")
    else:
        log_parser = WindowsLogParser(config)
        print("[*] Starting Windows log monitor...")
        print("[*] Watching: Windows Security Event Log")

    print("[*] Press Ctrl+C to stop.\n")

    # 6. Main loop – runs forever, checking logs every few seconds
    try:
        while True:
            # Parse new log events since last check
            events = log_parser.get_new_events()

            for event in events:
                # Feed each event into the threshold engine
                alert = engine.process_event(event)

                # If the engine decides this is an attack → send alert
                if alert:
                    print(f"[!] ALERT: {alert['message']}")
                    alerter.send(alert)

            # Wait before checking again (default: 10 seconds)
            time.sleep(config.get("check_interval_seconds", 10))

    except KeyboardInterrupt:
        print("\n[*] Monitor stopped by user.")
        sys.exit(0)


if __name__ == "__main__":
    main()
