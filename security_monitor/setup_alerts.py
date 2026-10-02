"""
setup_alerts.py
───────────────
Run this script ONCE to test your Email and Telegram alerts
before running the full monitor.

Usage:
  python3 setup_alerts.py --test email
  python3 setup_alerts.py --test telegram
  python3 setup_alerts.py --test both
"""

import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from modules.alerter import Alerter
from modules.config_loader import load_config


def test_alerts(channel):
    config = load_config("config/settings.yaml")
    alerter = Alerter(config)

    sample_alert = {
        "type":          "brute_force_detected",
        "source_ip":     "192.168.56.102",
        "failure_count": 5,
        "window_secs":   180,
        "os":            "linux",
        "last_username": "root",
        "detected_at":   "2026-03-25 11:00:00",
        "message": (
            "BRUTE-FORCE ATTACK DETECTED\n"
            "IP Address : 192.168.56.102\n"
            "Failures   : 5 in 180 seconds\n"
            "Last user  : root\n"
            "OS         : linux\n"
            "Detected at: 2026-03-25 11:00:00\n"
            "[TEST MESSAGE from setup_alerts.py]"
        )
    }

    if channel in ("email", "both"):
        print("\n[*] Sending test EMAIL alert...")
        if not config["email"].get("enabled"):
            print("  [!] Email is disabled in settings.yaml — set enabled: true first")
        else:
            alerter._send_email(sample_alert, sample_alert["message"])

    if channel in ("telegram", "both"):
        print("\n[*] Sending test TELEGRAM alert...")
        if not config["telegram"].get("enabled"):
            print("  [!] Telegram is disabled in settings.yaml — set enabled: true first")
        else:
            alerter._send_telegram(sample_alert["message"])

    print("\n[*] Done. Check your inbox / Telegram chat.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", choices=["email", "telegram", "both"],
                        default="both", help="Which channel to test")
    args = parser.parse_args()
    test_alerts(args.test)
