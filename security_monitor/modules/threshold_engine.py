"""
threshold_engine.py
───────────────────
This is the BRAIN of the monitoring system.

It keeps track of events over time and decides:
  "Has this IP address failed to login too many times? → ALERT!"

KEY CONCEPT – Sliding Time Window:
  We remember every failed login attempt with a timestamp.
  When a new failure comes in, we look back X seconds and
  count how many failures came from the same IP.
  If it's more than our threshold → brute-force attack detected!

  Example:
    Threshold = 5 failures in 180 seconds
    12:00:01  →  IP 1.2.3.4  failed  (count = 1)
    12:00:15  →  IP 1.2.3.4  failed  (count = 2)
    12:00:30  →  IP 1.2.3.4  failed  (count = 3)
    12:00:45  →  IP 1.2.3.4  failed  (count = 4)
    12:01:00  →  IP 1.2.3.4  failed  (count = 5) → 🚨 ALERT!
"""

import time
from collections import defaultdict
from datetime import datetime


class ThresholdEngine:
    """
    Tracks failed login events per IP address.
    Fires an alert when the count exceeds the configured threshold
    within the configured time window.
    """

    def __init__(self, config: dict):
        # Load threshold settings from config
        thresholds = config.get("thresholds", {})
        self.max_failures = thresholds.get("failed_login_count", 5)
        self.window_secs  = thresholds.get("failed_login_window_seconds", 180)

        # Storage: { "192.168.1.100": [timestamp1, timestamp2, ...] }
        # defaultdict means if an IP is new, it automatically gets an empty list
        self._failure_log = defaultdict(list)

        # Track which IPs we've already alerted about
        # (so we don't send 100 emails for one attack)
        self._alerted_ips = set()

        print(f"[*] Threshold engine ready:")
        print(f"    Rule: alert if >{self.max_failures} failures in {self.window_secs}s from same IP")

    def process_event(self, event: dict) -> dict | None:
        """
        Process a single event. Returns an alert dict if an attack
        is detected, otherwise returns None.

        Parameters:
            event: a dictionary from the log parser, e.g.:
                   { "type": "failed_login", "source_ip": "1.2.3.4", ... }

        Returns:
            alert dict if threshold exceeded, otherwise None
        """
        if event.get("type") != "failed_login":
            return None   # we only handle failed logins for now

        ip = event.get("source_ip", "unknown")
        now = time.time()   # current time as a number (Unix timestamp)

        # Record this failure for this IP
        self._failure_log[ip].append(now)

        # Remove failures that are OLDER than our time window
        # (we use a "sliding window" – only count recent events)
        cutoff = now - self.window_secs
        self._failure_log[ip] = [t for t in self._failure_log[ip] if t > cutoff]

        # Count how many failures are within the window
        failure_count = len(self._failure_log[ip])

        # Print a live status line (helpful for watching in terminal)
        print(f"  [{self._fmt_time(now)}] Failed login from {ip} "
              f"(username: {event.get('username','?')}) "
              f"– {failure_count}/{self.max_failures} in window")

        # Check if we've hit the threshold
        if failure_count >= self.max_failures and ip not in self._alerted_ips:

            # Mark this IP as alerted (prevent duplicate alerts)
            self._alerted_ips.add(ip)

            # Build and return the alert
            return {
                "type":          "brute_force_detected",
                "source_ip":     ip,
                "failure_count": failure_count,
                "window_secs":   self.window_secs,
                "os":            event.get("os", "unknown"),
                "last_username": event.get("username", "unknown"),
                "detected_at":   self._fmt_time(now),
                "message": (
                    f"🚨 BRUTE-FORCE ATTACK DETECTED\n"
                    f"IP Address : {ip}\n"
                    f"Failures   : {failure_count} in {self.window_secs} seconds\n"
                    f"Last user  : {event.get('username','unknown')}\n"
                    f"OS         : {event.get('os','unknown')}\n"
                    f"Detected at: {self._fmt_time(now)}"
                )
            }

        # Reset alert flag if failures have dropped (IP calmed down)
        # This allows future alerts if the attack resumes later
        if failure_count < self.max_failures and ip in self._alerted_ips:
            self._alerted_ips.discard(ip)

        return None   # no alert needed yet

    @staticmethod
    def _fmt_time(unix_ts: float) -> str:
        """Convert a Unix timestamp to a readable string."""
        return datetime.fromtimestamp(unix_ts).strftime("%Y-%m-%d %H:%M:%S")
