"""
linux_parser.py
───────────────
Reads Linux authentication logs (/var/log/auth.log or /var/log/secure)
and extracts security-relevant events such as failed SSH logins.

KEY CONCEPT: We use "regex" (regular expressions) to find patterns in
text – like searching for a specific sentence structure.

Example log line we are looking for (real output from OpenSSH):
  Oct  2 06:28:22 myserver sshd[1234]: Failed password for root from 192.168.1.100 port 52782 ssh2
  Oct  2 06:28:22 myserver sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 52790 ssh2

WHY WE ONLY COUNT "Failed password" LINES
─────────────────────────────────────────
This was verified against a real OpenSSH server (see docs/AUDIT.md, test A).
For a brute-force attempt sshd writes exactly ONE "Failed password" line per
rejected password. It *also* writes other lines for the same attempt:

    Invalid user admin from 1.2.3.4 port 52790
    Failed password for invalid user admin from 1.2.3.4 port 52790 ssh2
    Connection closed by invalid user admin 1.2.3.4 port 52790 [preauth]
    maximum authentication attempts exceeded for admin from 1.2.3.4 port 52790 ssh2 [preauth]

If we counted all of them the same attack would be counted 2-4 times and the
threshold would fire far too early (false positives). Counting only
"Failed password" gives exactly one hit per real attempt.
"""

import ipaddress   # stdlib – used to validate the IP we extracted
import os
import re          # regex – for pattern matching in text
from datetime import datetime

# ── Building blocks for the pattern ───────────────────────────
#
#  syslog timestamp : "Oct  2 06:28:22"  (note: syslog pads single-digit
#                     days with a space, so we allow 1-2 digits)
#  sshd prefix      : "sshd[1234]: "      – optional, because journald output
#                     ("journalctl -o cat") and "sshd -e" capture have no prefix
#  IPv4             : 192.168.1.100
#  IPv6             : 2001:db8::1        – the old [\d.]+ pattern silently
#                     truncated this to "2001", which corrupted the counter
_TIMESTAMP = r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})"
_SSHD      = r"(?:[^\s]+\s+)?sshd\[\d+\]:\s*"
_IP        = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]*:[0-9A-Fa-f:]*)"

# The one pattern we count. Matches both:
#   "Failed password for root from <ip> port <n> ssh2"
#   "Failed password for invalid user admin from <ip> port <n> ssh2"
FAILED_LOGIN_PATTERN = re.compile(
    r"(?:" + _TIMESTAMP + r"\s+)?"          # group 'ts'  (optional)
    r".*?"                                   # hostname / anything in between
    r"(?:" + _SSHD + r")?"                   # "host sshd[1234]: " (optional)
    r"Failed password for"
    r"(?P<invalid>\s+invalid user)?"         # group 'invalid' (optional)
    r"\s+(?P<user>\S+)"                      # group 'user'
    r"\s+from\s+" + _IP +                    # group 'ip'
    r"(?:\s+port\s+(?P<port>\d+))?"          # group 'port' (optional)
)


def _valid_ip(text: str) -> bool:
    """Return True only if the captured string is a real IPv4/IPv6 address."""
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


class LinuxLogParser:
    """
    Watches a Linux log file for new failed login attempts.

    Uses a technique called 'tailing' – we remember the byte offset we last
    read, and only read NEW bytes each time. On top of that we watch the
    file's inode and size so that log rotation (logrotate) does not blind us.
    """

    def __init__(self, config: dict, from_start: bool = False):
        self.log_file = config["linux"]["log_file"]
        self._last_position = 0    # byte offset we have read up to
        self._inode = None         # inode of the file we are tailing

        if not os.path.exists(self.log_file):
            print(f"[WARNING] Log file not found: {self.log_file}")
            print("  Are you running this on a Linux system with SSH enabled?")
            print("  (The monitor will start watching as soon as the file appears.)")
            return

        st = os.stat(self.log_file)
        self._inode = st.st_ino
        if from_start:
            # Replay/demo mode: process the file from the beginning.
            self._last_position = 0
        else:
            # Live mode: start at the END of the file so that we do not
            # re-process old history (and re-send old alerts) on start-up.
            self._last_position = st.st_size

    # ── public API ───────────────────────────────────────────
    def get_new_events(self) -> list:
        """
        Read any lines added to the log file since we last checked.
        Returns a list of event dictionaries (empty list if nothing new).
        """
        events = []

        if not os.path.exists(self.log_file):
            return events   # nothing to read (yet)

        try:
            st = os.stat(self.log_file)
        except OSError as e:
            print(f"[ERROR] Cannot stat log file: {e}")
            return events

        # ── log rotation / truncation handling ───────────────
        # logrotate either renames the file and creates a fresh one (new
        # inode) or copies and truncates it (same inode, size shrinks).
        # Without this check the saved offset sits past the end of the new
        # file and the monitor silently stops seeing anything, forever.
        if self._inode is not None and st.st_ino != self._inode:
            print("[*] Log file was rotated (new inode) – restarting from the top.")
            self._last_position = 0
        elif st.st_size < self._last_position:
            print("[*] Log file was truncated – restarting from the top.")
            self._last_position = 0
        self._inode = st.st_ino

        # ── read only the new bytes ──────────────────────────
        try:
            with open(self.log_file, "rb") as f:      # binary: immune to
                f.seek(self._last_position)           # broken UTF-8 bytes
                chunk = f.read()
        except OSError as e:
            print(f"[ERROR] Could not read log file: {e}")
            return events

        if not chunk:
            return events

        # Only consume complete lines. A half-written line stays in the file
        # until the writer finishes it.
        last_nl = chunk.rfind(b"\n")
        if last_nl == -1:
            return events
        consumed = chunk[: last_nl + 1]

        # errors="replace" – real auth.log files can contain junk bytes
        # (this happens for real when a rotated file is truncated while sshd
        # still holds an offset: the old offset region reads back as NULs).
        # The old code raised UnicodeDecodeError here and killed the monitor.
        text = consumed.decode("utf-8", errors="replace")
        self._last_position += len(consumed)

        for line in text.splitlines():
            event = self._parse_line(line)
            if event:
                events.append(event)

        return events

    # ── internals ────────────────────────────────────────────
    def _parse_line(self, line: str) -> dict | None:
        """
        Try to extract useful information from a single log line.
        Returns a dictionary if it is a failed login, otherwise None.

        Example output:
        {
            "type":      "failed_login",
            "timestamp": "Oct  2 06:28:22",
            "log_time":  "2026-10-02 06:28:22",
            "username":  "root",
            "source_ip": "192.168.1.100",
            "port":      "52782",
            "os":        "linux",
            "raw":       "<original log line>"
        }
        """
        match = FAILED_LOGIN_PATTERN.search(line)
        if not match:
            return None   # line was not a failed login → ignore it

        source_ip = match.group("ip")
        if not _valid_ip(source_ip):
            return None   # matched something that is not an address

        return {
            "type":         "failed_login",
            "timestamp":    match.group("ts") or "",
            "log_time":     self._parse_ts(match.group("ts")),
            "username":     match.group("user"),
            "invalid_user": bool(match.group("invalid")),
            "source_ip":    source_ip,
            "port":         match.group("port") or "",
            "os":           "linux",
            "raw":          line.strip(),
        }

    @staticmethod
    def _parse_ts(raw: str | None) -> str:
        """
        Convert a syslog timestamp ("Oct  2 06:28:22") into a full datetime
        string. syslog does not store the year, so we assume the current one
        (and step back a year if that would put the event in the future,
        which happens to entries read in early January).
        """
        if not raw:
            return ""
        try:
            dt = datetime.strptime(raw, "%b %d %H:%M:%S")
        except ValueError:
            return ""
        now = datetime.now()
        dt = dt.replace(year=now.year)
        if dt > now:
            dt = dt.replace(year=now.year - 1)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
