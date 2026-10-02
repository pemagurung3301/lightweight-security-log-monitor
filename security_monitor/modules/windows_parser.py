"""
windows_parser.py
─────────────────
Reads Windows Security Event Log using the Windows API.
Looks for Event ID 4625 (failed logon attempts).

NOTE: This only works on a real Windows machine.
     On Linux, it will print a message and return nothing.

KEY CONCEPT – Windows Event IDs:
  4624 = Successful logon
  4625 = Failed logon  ← we watch this one for brute-force
  4720 = New user account created
  4726 = User account deleted
"""

import sys
import time
from datetime import datetime


class WindowsLogParser:
    """
    Reads failed login events from the Windows Security Event Log.
    Uses the 'pywin32' library which provides access to Windows APIs.

    Install it with:  pip install pywin32
    """

    def __init__(self, config: dict):
        self._is_windows = sys.platform == "win32"

        if not self._is_windows:
            print("[WARNING] WindowsLogParser only works on Windows.")
            print("  If you're on Linux, use --os linux instead.")
            return

        # Import Windows-specific library (only available on Windows)
        try:
            import win32evtlog
            import win32evtlogutil
            import win32security
            self._win32evtlog     = win32evtlog
            self._win32evtlogutil = win32evtlogutil
            self._has_pywin32     = True
        except ImportError:
            print("[ERROR] pywin32 not installed.")
            print("  Run: pip install pywin32")
            self._has_pywin32 = False
            return

        # Open the Windows Security log
        self._server   = None           # None = local machine
        self._log_type = "Security"
        self._handle   = win32evtlog.OpenEventLog(self._server, self._log_type)
        self._last_record_number = self._get_latest_record_number()

        print(f"[*] Windows Event Log opened. Last record: {self._last_record_number}")

    def get_new_events(self) -> list:
        """
        Fetch new Windows Security events since last check.
        Filters for Event ID 4625 (failed logon).
        """
        events = []

        if not self._is_windows or not self._has_pywin32:
            return events

        win32evtlog = self._win32evtlog

        try:
            # Read events from the log (newest first)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            raw_events = win32evtlog.ReadEventLog(self._handle, flags, 0)

            for raw in raw_events:
                # Stop once we reach events we've already seen
                if raw.RecordNumber <= self._last_record_number:
                    break

                # We only care about failed logon (Event ID 4625)
                if raw.EventID == 4625:
                    event = self._parse_event(raw)
                    if event:
                        events.append(event)

            # Update our bookmark so we don't re-read these next time
            if raw_events:
                self._last_record_number = raw_events[0].RecordNumber

        except Exception as e:
            print(f"[ERROR] Could not read Windows Event Log: {e}")

        return events

    def _parse_event(self, raw_event) -> dict:
        """
        Extract useful fields from a raw Windows event.

        Windows event data is stored in an array called StringInserts.
        For Event ID 4625, the relevant positions are:
          Index  5 = Account name (username that failed)
          Index 19 = Source IP address
        """
        try:
            strings = raw_event.StringInserts or []

            username  = strings[5]  if len(strings) > 5  else "unknown"
            source_ip = strings[19] if len(strings) > 19 else "unknown"
            timestamp = str(raw_event.TimeGenerated)

            return {
                "type":      "failed_login",
                "timestamp": timestamp,
                "username":  username,
                "source_ip": source_ip,
                "os":        "windows",
                "event_id":  4625,
                "raw":       f"EventID=4625 user={username} ip={source_ip}"
            }
        except Exception as e:
            print(f"[ERROR] Could not parse Windows event: {e}")
            return None

    def _get_latest_record_number(self) -> int:
        """Find the most recent record number so we start fresh."""
        try:
            flags = self._win32evtlog.EVENTLOG_BACKWARDS_READ | \
                    self._win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = self._win32evtlog.ReadEventLog(self._handle, flags, 0)
            if events:
                return events[0].RecordNumber
        except Exception:
            pass
        return 0
