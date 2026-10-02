"""Tests for modules/windows_parser.py (the parts that can run off Windows)
   and dashboard.py"""
import json
import sys
import urllib.error
import urllib.request

import pytest

from modules.windows_parser import WindowsLogParser, FAILED_LOGON_EVENT_ID
from dashboard import Dashboard


# ── Windows parser guards ────────────────────────────────────
def test_parser_is_inert_off_windows(capsys):
    parser = WindowsLogParser({})
    if sys.platform == "win32":
        pytest.skip("guard only applies off Windows")
    assert parser._has_pywin32 is False
    assert parser.get_new_events() == []          # must not raise AttributeError
    assert "only works on Windows" in capsys.readouterr().out


def test_all_attributes_exist_without_pywin32():
    """Regression: _has_pywin32 could be undefined on some code paths."""
    parser = WindowsLogParser({})
    for attr in ("_is_windows", "_has_pywin32", "_handle", "_next_record"):
        assert hasattr(parser, attr)


def test_event_id_constant_is_4625():
    assert FAILED_LOGON_EVENT_ID == 4625


def test_event_id_high_bits_are_masked():
    """pywin32's EventID carries severity/facility bits in the high word."""
    raw = 0x80100000 | 4625
    assert (raw & 0xFFFF) == FAILED_LOGON_EVENT_ID


MESSAGE_4625 = (
    "An account failed to log on.\n"
    "Subject:\n\tSecurity ID:\t\tNULL SID\n"
    "Account For Which Logon Failed:\n"
    "\tSecurity ID:\t\tNULL SID\n"
    "\tAccount Name:\t\tvictim\n"
    "Network Information:\n"
    "\tWorkstation Name:\tWS1\n"
    "\tSource Network Address:\t203.0.113.9\n"
    "\tSource Port:\t\t51000\n"
)


class FakeRawEvent:
    """Stand-in for a pywin32 PyEventLogRecord."""
    def __init__(self, strings, message=None):
        self.StringInserts = strings
        self.TimeGenerated = "10/02/26 06:28:22"
        self._message = message

    def message(self):
        return self._message


def _parser_for_parsing():
    """A WindowsLogParser instance we can call _parse_event on, off Windows."""
    parser = WindowsLogParser.__new__(WindowsLogParser)
    parser._is_windows, parser._has_pywin32 = False, False
    parser._handle, parser._next_record = None, 0
    parser.log_type = "Security"
    parser._format_message = lambda raw: getattr(raw, "_message", "") or ""
    return parser


def test_string_inserts_indices_are_5_and_19():
    """Event 4625 message template: %6 TargetUserName, %20 IpAddress
    (0-based indices 5 and 19 in StringInserts). Layout below follows the
    documented 4625 insertion strings %1..%21."""
    inserts = [
        "S-1-0-0",        # %1  SubjectUserSid        -> 0
        "HOST$",          # %2  SubjectUserName       -> 1
        "WORKGROUP",      # %3  SubjectDomainName     -> 2
        "0x3e7",          # %4  SubjectLogonId        -> 3
        "S-1-0-0",        # %5  TargetUserSid         -> 4
        "victim",         # %6  TargetUserName        -> 5
        "",               # %7  TargetDomainName      -> 6
        "0xc000006d",     # %8  Status                -> 7
        "Unknown user name or bad password.",   # %9  FailureReason -> 8
        "0xc000006a",     # %10 SubStatus             -> 9
        "3",              # %11 LogonType             -> 10
        "NtLmSsp",        # %12 LogonProcessName      -> 11
        "NTLM",           # %13 AuthenticationPackage -> 12
        "WS1",            # %14 WorkstationName       -> 13
        "-",              # %15 TransitedServices     -> 14
        "-",              # %16 LmPackageName         -> 15
        "0",              # %17 KeyLength             -> 16
        "0x0",            # %18 ProcessId             -> 17
        "-",              # %19 ProcessName           -> 18
        "203.0.113.9",    # %20 IpAddress             -> 19
        "51000",          # %21 IpPort                -> 20
    ]
    assert len(inserts) == 21
    event = _parser_for_parsing()._parse_event(FakeRawEvent(inserts))
    assert event["username"] == "victim"
    assert event["source_ip"] == "203.0.113.9"
    assert event["port"] == "51000"
    assert event["event_id"] == 4625
    assert event["type"] == "failed_login"


def test_message_fallback_extracts_ip_and_user():
    """StringInserts is often unavailable for ETW events read through the
    legacy API; we then parse the rendered message instead."""
    event = _parser_for_parsing()._parse_event(FakeRawEvent([], MESSAGE_4625))
    assert event["username"] == "victim"
    assert event["source_ip"] == "203.0.113.9"


def test_console_logons_get_their_own_bucket():
    """A local logon has no network address; it must not be lumped in with
    remote attackers, or one locked-out user would look like a brute force."""
    event = _parser_for_parsing()._parse_event(FakeRawEvent([], ""))
    assert event["source_ip"] == "console"
    assert event["username"] == "unknown"


# ── dashboard ────────────────────────────────────────────────
def test_dashboard_serves_page_and_state():
    state = {"running": True, "source": "test", "started_at": "now", "uptime": "1s",
             "alert_channels": "none", "counters": {"total_failures": 2,
                                                    "total_alerts": 1, "last_alert": None},
             "threshold": {"max_failures": 5, "window_secs": 180, "cooldown_secs": 300,
                           "total_failures": 2, "total_alerts": 1, "active_ips": []},
             "alerts": [], "recent_events": []}
    dash = Dashboard(lambda: state, host="127.0.0.1", port=0)
    port = dash.start()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as r:
            page = r.read().decode()
        assert "Lightweight Security Log Monitor" in page

        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/state", timeout=5) as r:
            payload = json.loads(r.read().decode())
        assert payload["counters"]["total_failures"] == 2
        assert payload["source"] == "test"

        # urllib raises on 4xx, so the 404 has to be caught in order to be checked
        with pytest.raises(urllib.error.HTTPError) as err:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/nope", timeout=5)
        assert err.value.code == 404
    finally:
        dash.stop()


def test_dashboard_survives_a_broken_state_provider():
    def boom():
        raise RuntimeError("nope")

    dash = Dashboard(boom, host="127.0.0.1", port=0)
    port = dash.start()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/state", timeout=5) as r:
            payload = json.loads(r.read().decode())
        assert "error" in payload                      # reported, not a 500
    finally:
        dash.stop()
