"""
linux_parser.py
───────────────
Reads Linux authentication logs (/var/log/auth.log) and extracts
security-relevant events like failed SSH logins.

KEY CONCEPT: We use "regex" (regular expressions) to find patterns
in text – like searching for a specific sentence structure.

Example log line we are looking for:
  Nov 10 12:34:56 myserver sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
"""

import re       # regex – for pattern matching in text
import os
import time
from datetime import datetime


# ── The pattern we search for in each log line ───────────────
#
#  We want to capture:
#    (1) timestamp  e.g. "Nov 10 12:34:56"
#    (2) username   e.g. "root"
#    (3) IP address e.g. "192.168.1.100"
#
#  The regex below matches a line like:
#  "Nov 10 12:34:56 host sshd[...]: Failed password for root from 192.168.1.5 port ..."
#
FAILED_LOGIN_PATTERN = re.compile(
    r"(\w{3}\s+\d+\s[\d:]+)"              # group 1: timestamp
    r".+sshd\[\d+\]: Failed password for"  # sshd failed password
    r"(?:\s+invalid user)?"                # optional "invalid user"
    r"\s+(\S+)"                            # group 2: username
    r"\s+from\s+([\d.]+)"                  # group 3: IP address
)


class LinuxLogParser:
    """
    Watches a Linux log file for new failed login attempts.
    Uses a technique called 'tailing' – we remember where we
    last read, and only read NEW lines each time.
    """

    def __init__(self, config: dict):
        self.log_file = config["linux"]["log_file"]
        self._last_position = 0   # tracks where we last read up to

        # Start reading from the END of the file
        # (we don't want to re-process old history)
        if os.path.exists(self.log_file):
            with open(self.log_file, "r") as f:
                f.seek(0, 2)                   # jump to end of file
                self._last_position = f.tell() # remember this position
        else:
            print(f"[WARNING] Log file not found: {self.log_file}")
            print("  Are you running this on a Linux system with SSH enabled?")

    def get_new_events(self) -> list:
        """
        Read any new lines added to the log file since we last checked.
        Returns a list of event dictionaries.
        """
        events = []

        if not os.path.exists(self.log_file):
            return events   # nothing to read

        with open(self.log_file, "r") as f:
            # Jump to where we last finished reading
            f.seek(self._last_position)

            # Read all new lines
            new_lines = f.readlines()

            # Remember where we got up to for next time
            self._last_position = f.tell()

        # Parse each new line
        for line in new_lines:
            event = self._parse_line(line)
            if event:
                events.append(event)

        return events

    def _parse_line(self, line: str) -> dict | None:
        """
        Try to extract useful information from a single log line.
        Returns a dictionary if it's a failed login, otherwise None.

        Example output:
        {
            "type":      "failed_login",
            "timestamp": "Nov 10 12:34:56",
            "username":  "root",
            "source_ip": "192.168.1.100",
            "os":        "linux",
            "raw":       "<original log line>"
        }
        """
        match = FAILED_LOGIN_PATTERN.search(line)

        if match:
            return {
                "type":      "failed_login",
                "timestamp": match.group(1),
                "username":  match.group(2),
                "source_ip": match.group(3),
                "os":        "linux",
                "raw":       line.strip()
            }

        return None   # line was not a failed login → ignore it
