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
  If the count reaches our threshold → brute-force attack detected!

  Example:
    Threshold = 5 failures in 180 seconds
    12:00:01  →  IP 1.2.3.4  failed  (count = 1)
    12:00:15  →  IP 1.2.3.4  failed  (count = 2)
    12:00:30  →  IP 1.2.3.4  failed  (count = 3)
    12:00:45  →  IP 1.2.3.4  failed  (count = 4)
    12:01:00  →  IP 1.2.3.4  failed  (count = 5) → 🚨 ALERT!

NOTE ON "5" : the alert fires on the 5th failure (count >= 5), which is what
the README promises. An earlier version of this file printed the rule as
"alert if >5" while the code used ">=", so the console and the docs disagreed.
"""

import time
from collections import defaultdict
from datetime import datetime

# How often (seconds) we sweep out IPs that have gone quiet. Without this the
# dictionaries grow for the whole lifetime of the process – a monitor left
# running for weeks would slowly eat memory.
CLEANUP_INTERVAL_SECONDS = 60


class ThresholdEngine:
    """
    Tracks failed login events per IP address.
    Fires an alert when the count reaches the configured threshold
    within the configured time window.
    """

    def __init__(self, config: dict, verbose: bool = True):
        # Load threshold settings from config
        thresholds = config.get("thresholds", {}) or {}
        self.max_failures = int(thresholds.get("failed_login_count", 5))
        self.window_secs  = int(thresholds.get("failed_login_window_seconds", 180))
        # How long we stay silent about the same IP after alerting on it.
        # Prevents one long attack from filling the inbox with identical mails,
        # but still re-alerts if the attack keeps going.
        self.cooldown_secs = int(thresholds.get(
            "alert_cooldown_seconds", max(self.window_secs, 300)))

        # Storage: { "192.168.1.100": [timestamp1, timestamp2, ...] }
        # defaultdict means if an IP is new, it automatically gets an empty list
        self._failure_log = defaultdict(list)
        # { ip: set(usernames it has tried) } – makes the alert much more useful
        self._usernames   = defaultdict(set)
        # { ip: unix time of the last alert we sent for it }
        self._alerted_at  = {}
        # when we last swept stale entries
        self._last_cleanup = time.time()

        self.verbose = verbose
        self.total_failures = 0
        self.total_alerts   = 0

        if verbose:
            print("[*] Threshold engine ready:")
            print(f"    Rule: alert on {self.max_failures} or more failures "
                  f"in {self.window_secs}s from the same IP "
                  f"(re-alert after {self.cooldown_secs}s)")

    # ── main entry point ─────────────────────────────────────
    def process_event(self, event: dict) -> dict | None:
        """
        Process a single event. Returns an alert dict if an attack
        is detected, otherwise returns None.

        Parameters:
            event: a dictionary from the log parser, e.g.
                   { "type": "failed_login", "source_ip": "1.2.3.4", ... }
        """
        if event.get("type") != "failed_login":
            return None   # we only handle failed logins for now

        ip = event.get("source_ip") or "unknown"
        username = event.get("username") or "unknown"
        now = time.time()   # current time as a number (Unix timestamp)

        # Record this failure for this IP
        self._failure_log[ip].append(now)
        self._usernames[ip].add(username)
        self.total_failures += 1

        # Remove failures that are OLDER than our time window
        # (we use a "sliding window" – only count recent events)
        cutoff = now - self.window_secs
        self._failure_log[ip] = [t for t in self._failure_log[ip] if t > cutoff]

        # Count how many failures are within the window
        failure_count = len(self._failure_log[ip])

        # Print a live status line (helpful for watching in terminal)
        if self.verbose:
            print(f"  [{self._fmt_time(now)}] Failed login from {ip} "
                  f"(username: {username}) "
                  f"– {failure_count}/{self.max_failures} in window")

        # Maybe sweep memory
        self._maybe_cleanup(now)

        # ── should we alert? ─────────────────────────────────
        last_alert = self._alerted_at.get(ip)
        breached   = failure_count >= self.max_failures
        cooled_down = (last_alert is None) or (now - last_alert >= self.cooldown_secs)

        if breached and cooled_down:
            self._alerted_at[ip] = now
            self.total_alerts += 1
            usernames = sorted(self._usernames[ip])
            shown = ", ".join(usernames[:8])
            if len(usernames) > 8:
                shown += f", … (+{len(usernames) - 8} more)"

            return {
                "type":          "brute_force_detected",
                "source_ip":     ip,
                "failure_count": failure_count,
                "window_secs":   self.window_secs,
                "os":            event.get("os", "unknown"),
                "last_username": username,
                "usernames":     usernames,
                "detected_at":   self._fmt_time(now),
                "message": (
                    f"🚨 BRUTE-FORCE ATTACK DETECTED\n"
                    f"IP Address : {ip}\n"
                    f"Failures   : {failure_count} in {self.window_secs} seconds\n"
                    f"Usernames  : {shown}\n"
                    f"OS         : {event.get('os', 'unknown')}\n"
                    f"Detected at: {self._fmt_time(now)}"
                )
            }

        return None   # no alert needed

    # ── introspection (used by the dashboard and the tests) ──
    def get_stats(self) -> dict:
        """Snapshot of what the engine currently knows. Powers the web GUI."""
        now = time.time()
        cutoff = now - self.window_secs
        active = []
        for ip, times in self._failure_log.items():
            recent = [t for t in times if t > cutoff]
            if not recent:
                continue
            active.append({
                "source_ip":     ip,
                "failure_count": len(recent),
                "usernames":     sorted(self._usernames.get(ip, set()))[:10],
                "last_seen":     self._fmt_time(max(recent)),
                "breached":      len(recent) >= self.max_failures,
            })
        active.sort(key=lambda a: a["failure_count"], reverse=True)
        return {
            "max_failures":   self.max_failures,
            "window_secs":    self.window_secs,
            "cooldown_secs":  self.cooldown_secs,
            "total_failures": self.total_failures,
            "total_alerts":   self.total_alerts,
            "active_ips":     active,
        }

    def reset(self):
        """Clear all memory (used by the tests)."""
        self._failure_log.clear()
        self._usernames.clear()
        self._alerted_at.clear()
        self.total_failures = 0
        self.total_alerts = 0

    # ── internals ────────────────────────────────────────────
    def _maybe_cleanup(self, now: float):
        if now - self._last_cleanup < CLEANUP_INTERVAL_SECONDS:
            return
        self._last_cleanup = now
        cutoff = now - max(self.window_secs, self.cooldown_secs)
        for ip in list(self._failure_log.keys()):
            if not [t for t in self._failure_log[ip] if t > cutoff]:
                del self._failure_log[ip]
                self._usernames.pop(ip, None)
                last = self._alerted_at.get(ip)
                if last is None or last < cutoff:
                    self._alerted_at.pop(ip, None)

    @staticmethod
    def _fmt_time(unix_ts: float) -> str:
        """Convert a Unix timestamp to a readable string."""
        return datetime.fromtimestamp(unix_ts).strftime("%Y-%m-%d %H:%M:%S")
