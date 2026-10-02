"""
Tests for modules/linux_parser.py

Every case here is based on output captured from a real OpenSSH server
(see docs/AUDIT.md, "Verification A").
"""
import os

import pytest

from modules.linux_parser import LinuxLogParser

# Real lines captured from `sshd -e` during a live brute-force test.
REAL_SSHD_LINES = [
    "Oct  2 06:28:22 vm sshd[1503]: Failed password for root from 127.0.0.1 port 52782 ssh2",
    "Oct  2 06:28:23 vm sshd[1503]: Failed password for invalid user admin from 127.0.0.1 port 52790 ssh2",
]


def make_parser(tmp_path, filename="auth.log", content="", from_start=False):
    path = tmp_path / filename
    path.write_text(content, encoding="utf-8")
    return LinuxLogParser({"linux": {"log_file": str(path)}}, from_start=from_start), path


# ── parsing ──────────────────────────────────────────────────
def test_parses_real_sshd_failed_password_line(tmp_path):
    parser, _ = make_parser(tmp_path)
    for line in REAL_SSHD_LINES:
        event = parser._parse_line(line)
        assert event is not None, line
        assert event["type"] == "failed_login"
        assert event["source_ip"] == "127.0.0.1"
        assert event["os"] == "linux"


def test_username_extracted_for_invalid_user(tmp_path):
    parser, _ = make_parser(tmp_path)
    event = parser._parse_line(REAL_SSHD_LINES[1])
    assert event["username"] == "admin"
    assert event["invalid_user"] is True


def test_plain_user_is_not_flagged_invalid(tmp_path):
    parser, _ = make_parser(tmp_path)
    assert parser._parse_line(REAL_SSHD_LINES[0])["invalid_user"] is False


def test_ipv6_address_is_not_truncated(tmp_path):
    """Regression: the old [\\d.]+ pattern turned 2001:db8::1 into '2001'."""
    parser, _ = make_parser(tmp_path)
    event = parser._parse_line(
        "Oct  2 06:28:22 vm sshd[999]: Failed password for root from 2001:db8::1 port 22 ssh2")
    assert event["source_ip"] == "2001:db8::1"


def test_works_without_syslog_prefix(tmp_path):
    """`sshd -e` / `journalctl -o cat` output has no timestamp or sshd[pid]."""
    parser, _ = make_parser(tmp_path)
    event = parser._parse_line("Failed password for root from 10.0.0.5 port 22 ssh2")
    assert event["source_ip"] == "10.0.0.5"
    assert event["username"] == "root"


def test_non_failure_lines_are_ignored(tmp_path):
    parser, _ = make_parser(tmp_path)
    for line in [
        "Oct  2 06:28:22 vm sshd[1503]: Accepted password for bob from 127.0.0.1 port 52782 ssh2",
        "Oct  2 06:28:22 vm sshd[1503]: Invalid user admin from 127.0.0.1 port 52790",
        "Oct  2 06:28:22 vm sshd[1503]: Connection closed by invalid user admin 127.0.0.1 port 52790 [preauth]",
        "Oct  2 06:28:22 vm systemd[1]: Started Session 3 of user bob.",
        "",
    ]:
        assert parser._parse_line(line) is None, line


def test_one_counted_event_per_attempt_not_two(tmp_path):
    """
    A real attempt writes 'Invalid user ...' AND 'Failed password ...'.
    Counting both would halve the effective threshold, so only the
    'Failed password' line may produce an event.
    """
    parser, path = make_parser(tmp_path, from_start=True)
    path.write_text(
        "Oct  2 06:28:22 vm sshd[1503]: Invalid user admin from 127.0.0.1 port 52790\n"
        "Oct  2 06:28:22 vm sshd[1503]: Failed password for invalid user admin from 127.0.0.1 port 52790 ssh2\n",
        encoding="utf-8")
    assert len(parser.get_new_events()) == 1


def test_syslog_timestamp_gets_a_year(tmp_path):
    parser, _ = make_parser(tmp_path)
    event = parser._parse_line(REAL_SSHD_LINES[0])
    assert event["timestamp"] == "Oct  2 06:28:22"
    assert event["log_time"].endswith("10-02 06:28:22")
    assert len(event["log_time"].split("-")[0]) == 4      # a 4-digit year


# ── tailing behaviour ────────────────────────────────────────
def test_only_new_lines_are_returned(tmp_path):
    parser, path = make_parser(tmp_path, content=REAL_SSHD_LINES[0] + "\n")
    assert parser.get_new_events() == []                  # started at EOF
    with path.open("a", encoding="utf-8") as f:
        f.write(REAL_SSHD_LINES[1] + "\n")
    events = parser.get_new_events()
    assert len(events) == 1
    assert parser.get_new_events() == []                  # not re-reported


def test_survives_log_rotation(tmp_path):
    """Regression: after logrotate the saved offset sat past EOF and the
    monitor silently stopped seeing anything, forever."""
    parser, path = make_parser(tmp_path, content="x" * 500)
    parser.get_new_events()
    path.write_text(REAL_SSHD_LINES[0] + "\n", encoding="utf-8")   # truncate + rewrite
    events = parser.get_new_events()
    assert len(events) == 1
    assert events[0]["source_ip"] == "127.0.0.1"


def test_survives_a_renamed_rotated_file(tmp_path):
    parser, path = make_parser(tmp_path, content="x" * 500)
    parser.get_new_events()
    os.replace(path, str(path) + ".1")
    fresh = tmp_path / "auth.log"
    fresh.write_text(REAL_SSHD_LINES[0] + "\n", encoding="utf-8")
    assert len(parser.get_new_events()) == 1


def test_survives_binary_junk_bytes(tmp_path):
    """Regression: a stray 0xff byte raised UnicodeDecodeError and killed
    the monitor. This happens for real when a rotated file is truncated
    while sshd still holds an offset (the gap reads back as NUL bytes)."""
    path = tmp_path / "auth.log"
    path.write_bytes(b"", )
    parser = LinuxLogParser({"linux": {"log_file": str(path)}})
    with path.open("ab") as f:
        f.write(REAL_SSHD_LINES[0].encode() + b" \xff\xfe junk\n")
    events = parser.get_new_events()                      # must not raise
    assert len(events) == 1


def test_partial_line_is_not_consumed(tmp_path):
    parser, path = make_parser(tmp_path)
    with path.open("a") as f:
        f.write("Oct  2 06:28:22 vm sshd[1503]: Failed passw")   # no newline yet
    assert parser.get_new_events() == []
    with path.open("a") as f:
        f.write("ord for root from 127.0.0.1 port 52782 ssh2\n")
    events = parser.get_new_events()
    assert len(events) == 1
    assert events[0]["source_ip"] == "127.0.0.1"


def test_missing_file_is_not_fatal(tmp_path):
    parser = LinuxLogParser({"linux": {"log_file": str(tmp_path / "nope.log")}})
    assert parser.get_new_events() == []
    # and it starts working once the file appears
    (tmp_path / "nope.log").write_text(REAL_SSHD_LINES[0] + "\n", encoding="utf-8")
    assert len(parser.get_new_events()) == 1
