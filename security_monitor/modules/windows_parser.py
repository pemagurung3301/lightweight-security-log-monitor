"""
windows_parser.py
─────────────────
Reads the Windows Security Event Log using the Windows API.
Looks for Event ID 4625 (failed logon attempts).

NOTE: This only works on a real Windows machine.
     On Linux, it prints a message and returns nothing.

KEY CONCEPT – Windows Event IDs:
  4624 = Successful logon
  4625 = Failed logon  ← we watch this one for brute-force
  4720 = New user account created
  4726 = User account deleted

HOW WE POLL FOR NEW RECORDS (important!)
────────────────────────────────────────
ReadEventLog has two modes (Microsoft docs):

  EVENTLOG_SEQUENTIAL_READ – "proceeds sequentially from the last call to
                              ReadEventLog using this handle"
  EVENTLOG_SEEK_READ       – "proceeds from the record given in dwRecordOffset"

The original version of this file called a *sequential* read to find the
newest record number when it started. That drains the read pointer all the
way down to the OLDEST record, so every later sequential read continued
backwards from there and returned nothing. Result: the monitor opened the
log, printed "Windows Event Log opened" and then never produced a single
event, no matter how many failed logons happened.

We now use SEEK_READ + FORWARDS_READ from `last_record + 1`, which reads
exactly the new records and nothing else.

FIELD POSITIONS
───────────────
For Event 4625 the message template's insertion strings are 1-based (%1..%21);
StringInserts is the same list 0-based:

   %6  TargetUserName → index 5      (the account that was attacked)
   %20 IpAddress      → index 19     (where the attempt came from)

Because ETW-published events do not always expose StringInserts through the
legacy ReadEventLog API, we also fall back to formatting the event message
and reading "Source Network Address:" out of it.
"""

import re
import sys

FAILED_LOGON_EVENT_ID = 4625

_IP_IN_MESSAGE = re.compile(r"Source Network Address:\s*([0-9A-Fa-f:.]+)")
_USER_IN_MESSAGE = re.compile(r"Account For Which Logon Failed:.*?Account Name:\s*(\S+)",
                              re.DOTALL)


class WindowsLogParser:
    """
    Reads failed logon events from the Windows Security Event Log.
    Uses the 'pywin32' library which provides access to Windows APIs.

    Install it with:  pip install pywin32
    """

    def __init__(self, config: dict):
        # Always define these, whatever platform we are on, so that
        # get_new_events() can never hit an AttributeError.
        self._is_windows    = sys.platform == "win32"
        self._has_pywin32   = False
        self._win32evtlog   = None
        self._handle        = None
        self._next_record   = 0
        self.log_type       = config.get("windows", {}).get("log_name", "Security") \
            if isinstance(config.get("windows"), dict) else "Security"

        if not self._is_windows:
            print("[WARNING] WindowsLogParser only works on Windows.")
            print("  If you're on Linux, use --os linux instead.")
            return

        # Import Windows-specific library (only available on Windows)
        try:
            import win32evtlog
            self._win32evtlog = win32evtlog
            self._has_pywin32 = True
        except ImportError:
            print("[ERROR] pywin32 not installed.")
            print("  Run: pip install pywin32")
            return

        if not self._open_log():
            return

        print(f"[*] Windows Event Log '{self.log_type}' opened. "
              f"Watching from record {self._next_record}.")

    # ── public API ───────────────────────────────────────────
    def get_new_events(self) -> list:
        """
        Fetch new Windows Security events since the last check.
        Filters for Event ID 4625 (failed logon).
        """
        events = []
        if not self._is_windows or not self._has_pywin32 or not self._handle:
            return events

        win32evtlog = self._win32evtlog
        # SEEK to the first record we have not seen and read forwards.
        flags = win32evtlog.EVENTLOG_SEEK_READ | win32evtlog.EVENTLOG_FORWARDS_READ
        offset = self._next_record

        while True:
            try:
                batch = win32evtlog.ReadEventLog(self._handle, flags, offset)
            except Exception:
                # No more records (end of log), or the record was rotated away.
                break
            if not batch:
                break

            for raw in batch:
                # EventID carries severity/facility bits in the high word.
                if (raw.EventID & 0xFFFF) == FAILED_LOGON_EVENT_ID:
                    event = self._parse_event(raw)
                    if event:
                        events.append(event)

            offset = batch[-1].RecordNumber + 1
            # only move the bookmark once we know we consumed the batch
            self._next_record = offset

            if len(batch) == 0:
                break

        if not events:
            self._recheck_handle_alive()

        return events

    def close(self):
        """Release the event log handle (called when the monitor stops)."""
        if self._handle is not None and self._has_pywin32:
            try:
                self._win32evtlog.CloseEventLog(self._handle)
            except Exception:
                pass
            self._handle = None

    # ── internals ────────────────────────────────────────────
    def _open_log(self) -> bool:
        win32evtlog = self._win32evtlog
        try:
            self._handle = win32evtlog.OpenEventLog(None, self.log_type)
            self._next_record = self._highest_record_number() + 1
            return True
        except Exception as e:
            print(f"[ERROR] Could not open the Windows '{self.log_type}' log: {e}")
            print("  Are you running the terminal as Administrator?")
            self._handle = None
            return False

    def _highest_record_number(self) -> int:
        """Newest record number, without draining the read pointer."""
        w = self._win32evtlog
        try:
            oldest = w.GetOldestEventLogRecord(self._handle)
            count  = w.GetNumberOfEventLogRecords(self._handle)
            if count:
                return oldest + count - 1
        except Exception:
            pass
        return 0

    def _recheck_handle_alive(self):
        """If the log was cleared/wrapped our bookmark may be stale."""
        w = self._win32evtlog
        try:
            oldest = w.GetOldestEventLogRecord(self._handle)
            if self._next_record < oldest:
                print("[*] Event log was cleared – resetting the bookmark.")
                self._next_record = oldest
        except Exception:
            pass

    def _parse_event(self, raw_event) -> dict | None:
        """
        Extract useful fields from a raw Windows event.

        Tries the message insertion strings first, then falls back to parsing
        the formatted event message.
        """
        try:
            strings = list(raw_event.StringInserts or [])
        except Exception:
            strings = []

        username  = strings[5]  if len(strings) > 5  else ""
        source_ip = strings[19] if len(strings) > 19 else ""

        # Fall back to the rendered message when the inserts are unavailable
        # or empty (common for ETW events read through the legacy API).
        if not source_ip or source_ip == "-" or not username:
            text = self._format_message(raw_event)
            if text:
                m = _IP_IN_MESSAGE.search(text)
                if m and (not source_ip or source_ip == "-"):
                    source_ip = m.group(1)
                m = _USER_IN_MESSAGE.search(text)
                if m and not username:
                    username = m.group(1)

        username  = (username  or "unknown").strip() or "unknown"
        source_ip = (source_ip or "").strip()

        # Console/RDP-from-localhost logons have no network address. Give them
        # their own bucket so they never mix with real remote attackers.
        if not source_ip or source_ip in {"-", "::1", "127.0.0.1"}:
            source_ip = "console"

        try:
            timestamp = str(raw_event.TimeGenerated)
        except Exception:
            timestamp = ""

        return {
            "type":       "failed_login",
            "timestamp":  timestamp,
            "log_time":   timestamp,
            "username":   username,
            "source_ip":  source_ip,
            "port":       (strings[20] if len(strings) > 20 else "") or "",
            "os":         "windows",
            "event_id":   FAILED_LOGON_EVENT_ID,
            "raw":        f"EventID={FAILED_LOGON_EVENT_ID} user={username} ip={source_ip}",
        }

    def _format_message(self, raw_event) -> str:
        try:
            import win32evtlogutil
            return win32evtlogutil.SafeFormatMessage(raw_event, self.log_type)
        except Exception:
            return ""
