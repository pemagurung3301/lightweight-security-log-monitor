# Code Audit — Lightweight Security Log Monitor

Full review of the repository as committed at `aed92b7`. Every finding below was
**reproduced by running the code**, not by reading it. The command that produced
each piece of evidence is listed with it, so any claim can be re-checked.

Environment used: Ubuntu container, Python 3.11.2, PyYAML 6.0.3, plus a **real
OpenSSH server** started locally (`/usr/sbin/sshd -e`) to produce genuine
`Failed password` log lines.

---

## 1. Action required from you (cannot be fixed in code)

| # | Finding | What to do |
|---|---------|------------|
| 0 | **A live Telegram bot token was committed** in `config/settings.yaml` (bot id `8918463892`, token redacted here). It is in commit `aed92b7`, so it is in the repository history and must be treated as public. | Open Telegram → `@BotFather` → `/revoke` → pick that bot. Then create a new bot. Do not paste the new token into the YAML — use `export TELEGRAM_BOT_TOKEN='…'` (the alerter reads it). The personal Gmail addresses that were in the file have also been replaced with placeholders. |

Verified with: `git log --all -S "<the bot id>"` → `aed92b7`, and `git grep -n "<the bot id>" HEAD` → `security_monitor/config/settings.yaml:39` in that commit.

---

## 2. Bugs that would have broken the demo

### 2.1 The monitor could not be started from the repository root — FIXED
`monitor.py` loaded the config with a path relative to the shell's working
directory (`load_config("config/settings.yaml")`), but the README's folder layout
invites you to run it from the project root.

```
$ python3 security_monitor/monitor.py --os linux
[ERROR] Config file not found: config/settings.yaml
```

**Fix:** the config path is now resolved next to `monitor.py`, and `--config PATH`
lets you point at any file. `sys.path` is set up so `from modules…` works from
any directory. Covered by `tests/test_monitor_cli.py::test_config_is_found_from_any_working_directory`.

### 2.2 A half-configured email section killed the whole monitor — FIXED
`Alerter._send_email` read `cfg["sender_email"]` *outside* its `try` block, and
`monitor.py` only caught `KeyboardInterrupt`.

```
>>> Alerter({"email": {"enabled": True, ...}}).send(alert)
CRASH: KeyError -> 'sender_email'
```

**Fix:** config is validated first, the send is wrapped, and `Alerter.send()` is
also wrapped at the call site — an alerting failure can no longer stop detection.
`tests/test_alerter.py::test_missing_email_fields_do_not_crash`.

### 2.3 One junk byte in `auth.log` crashed the monitor — FIXED
The parser opened the file in text mode, so any non-UTF-8 byte raised out of
`readlines()` and terminated the process.

```
CRASH: UnicodeDecodeError 'utf-8' codec can't decode byte 0xff in position 81
```

This is not hypothetical: while testing with a real sshd, truncating a log file
that sshd still held open produced a region of NUL bytes at the old offset —
exactly the situation `logrotate` creates.

**Fix:** read in binary, consume only whole lines, decode with
`errors="replace"`. `tests/test_linux_parser.py::test_survives_binary_junk_bytes`.

### 2.4 Log rotation made the monitor permanently blind — FIXED
The parser remembered a byte offset and never checked whether the file had been
rotated. After `logrotate` the offset sat past the end of the new file, so
`readlines()` returned `[]` forever — silently.

```
before rotation, events seen: 1
after truncation, new line present in file: Oct  2 07:00:00 vm sshd[999]: Failed password ...
after rotation, events seen: 0        <-- blind from here on
```

On a real server `logrotate` runs daily, so the monitor would have stopped
working every night with no error message.

**Fix:** track the inode and the size; reset the offset when either changes.
`test_survives_log_rotation`, `test_survives_a_renamed_rotated_file`.

### 2.5 The Windows parser could never produce an event — FIXED (not runnable here)
`__init__` called `_get_latest_record_number()`, which did a full
`EVENTLOG_SEQUENTIAL_READ | EVENTLOG_BACKWARDS_READ`. Per Microsoft's
documentation, sequential reads "proceed sequentially from the last call to
`ReadEventLog` **using this handle**" — so that first call drained the read
pointer all the way to the *oldest* record. Every later poll then continued
backwards from the oldest record and returned nothing, no matter how many failed
logons occurred.

**Fix:** poll with `EVENTLOG_SEEK_READ | EVENTLOG_FORWARDS_READ` from
`last_record + 1`, clamp the bookmark with `GetOldestEventLogRecord` when the log
is cleared, mask the event id (`raw.EventID & 0xFFFF` — the high word carries
severity/facility bits), and close the handle on shutdown.

⚠️ **Honest caveat:** this sandbox is Linux, so the Windows code path could not
be executed. It is covered by unit tests for everything that does not need the
Win32 API (guards, attribute presence, event-id masking, field extraction).
**You must re-test `--os windows` on a real Windows VM before the viva** —
see `docs/SHOWCASE.md` §5.

---

## 3. Detection-quality bugs

### 3.1 IPv6 addresses were silently truncated — FIXED
The IP group was `([\d.]+)`, which matched only the leading digits of an IPv6
address:

```
MATCH  ... Failed password for root from 2001:db8::1 port 22 ssh2  -> ip=2001
```

Every attacker on IPv6 was counted under the same fake IP `2001`, so counts were
wrong in both directions. **Fix:** a proper IPv4|IPv6 pattern validated with the
`ipaddress` module; matches that are not real addresses are dropped.

### 3.2 Printed rule contradicted the code — FIXED
The banner said `alert if >5 failures` while the test was `failure_count >= 5`,
and the README said "exceeds 5". The code and the README were right; the banner
was wrong.

### 3.3 Alert state and memory — FIXED
`_alerted_ips` was a set with a reset branch that only ran when a new event
arrived, and nothing ever evicted an IP that had gone quiet, so both
dictionaries grew for the lifetime of the process. Replaced with an explicit
`alert_cooldown_seconds` (configurable) plus a periodic sweep of stale IPs, and
the alert now lists **every username the attacker tried**, which makes it far
more useful in a report.

### 3.4 Telegram alerts could be rejected by the API — FIXED
Requests were sent with `parse_mode: HTML` but the text was not escaped. The
username comes straight from the log file, i.e. it is attacker-controlled, so a
`<` or `&` in it makes Telegram answer HTTP 400 and the alert is lost. Now
escaped and wrapped in `<pre>`. `tests/test_alerter.py::test_telegram_payload_escapes_html`.

### 3.5 A dead SMTP server could hang the monitor — FIXED
`smtplib.SMTP(host, port)` had no timeout. Now `timeout=20`.

### 3.6 Windows field indices — checked, they were correct
`StringInserts[5]` and `StringInserts[19]` match the documented Event 4625
insertion strings `%6 TargetUserName` and `%20 IpAddress` (0-based 5 and 19).
No change needed. However, ETW-published events frequently expose **no**
`StringInserts` through the legacy `ReadEventLog` API, so a fallback that parses
the rendered message (`Source Network Address:` / `Account Name:`) was added,
and console logons (no network address) now get their own `console` bucket
instead of being mixed with remote attackers.

### 3.7 What was deliberately *not* changed
The core pattern `Failed password for [invalid user] <user> from <ip>` is
correct — confirmed against real sshd output. Other lines the same attempt
produces are **not** counted on purpose:

```
Invalid user admin from 127.0.0.1 port 52790
Failed password for invalid user admin from 127.0.0.1 port 52790 ssh2   <-- counted
Connection closed by invalid user admin 127.0.0.1 port 52790 [preauth]
maximum authentication attempts exceeded for admin from 127.0.0.1 ... [preauth]
```

Six real password attempts on one connection produced exactly six
`Failed password` lines plus one `maximum authentication attempts exceeded`
line. Counting the extra lines would inflate the counter and fire the threshold
early. `tests/test_linux_parser.py::test_one_counted_event_per_attempt_not_two`
locks this in.

---

## 4. Setup / packaging bugs

| # | Finding | Fix |
|---|---------|-----|
| 4.1 | `requirements.txt` had `pywin32` commented out, so on Windows `pip install -r requirements.txt` installed nothing Windows-specific and the parser printed "pywin32 not installed". | Environment marker: `pywin32>=306 ; sys_platform == "win32"`. |
| 4.2 | `1_install_dependencies.sh` ran `pip3 install pyyaml`, which fails on Ubuntu 23.04+ with *externally-managed-environment* (PEP 668). | Uses `apt install python3-yaml`, with pip fallbacks. |
| 4.3 | `5_check_logs.sh` filtered with `grep -E "Failed\|Invalid\|Accepted\|error\|$"`. The trailing `\|$` matches every line, so the filter did nothing (verified: 4 of 4 sample lines matched). | Pattern fixed; added a per-IP failure summary. |
| 4.4 | README said to set `log_file: logs/test_auth.log`, but the committed sample was at `tests/logs/test_auth.log` — and the monitor starts at end-of-file, so the sample was never read anyway. | `simulate_attack.py` now reads `log_file` **from settings.yaml**, so the simulator can never write to a different file than the one being watched. |
| 4.5 | `--os windows` on Linux printed a warning and then looped forever doing nothing. | Exits with code 2 and a message pointing at `--os linux` / `--replay`. |
| 4.6 | No `--os` auto-detection; `--os` was required. | `--os auto` is the default. |
| 4.7 | 11 compiled `__pycache__/*.pyc` files (two different Python versions) were committed and there was no `.gitignore`. | Removed from the index, `.gitignore` added. |
| 4.8 | Unused imports (`os`, `time`, `datetime` in `linux_parser.py`; `os` in `monitor.py`). | Removed. |

---

## 5. What the code now has that it did not have

- **53 automated tests** (`python3 -m pytest tests/ -q`) — the `tests/` folder
  previously held only a manual simulator.
- **An alert file** (`logs/alerts.jsonl`, one JSON record per alert). This is
  your evidence trail for the report: it exists even with email and Telegram
  switched off.
- **`--replay <logfile>`** — run a recorded attack through the whole pipeline on
  any OS, including one with no SSH server. Ideal for a projector demo.
- **`--gui`** — a web dashboard built only with the standard library
  (`dashboard.py`, no new dependency), for the GUI half of the demonstration.
- **`--test-alert`** — verify the email/Telegram plumbing in one command.
- **Secrets via environment variables** (`SMTP_PASSWORD`, `TELEGRAM_BOT_TOKEN`,
  `TELEGRAM_CHAT_ID`), so nothing sensitive has to live in Git.

---

## 6. Known limitations (state these in the viva — they are design choices)

1. **The time window uses the wall clock**, not the timestamp inside the log
   line. Correct for live tailing; in `--replay` mode every event is "now".
2. **Detection is threshold-based only.** No reputation lists, geo-IP, or
   automated blocking (no `fail2ban`/`iptables` response). Response is
   notification, which matches the "lightweight, for SMEs" scope.
3. **`/var/log/auth.log` requires a syslog daemon.** On journald-only systems
   use `journalctl -f _COMM=sshd`, or install `rsyslog`.
   `vm_setup_scripts/2_enable_ssh.sh` checks and tells you which you have.
4. **The Windows path is untested in this environment** (see §2.5).
5. **Only failed SSH logins are counted** on Linux. `sudo` failures, `su`, and
   web-app logins are out of scope.
6. **A determined attacker below the threshold is invisible** — 4 failures every
   4 minutes never reaches "5 in 180s". Lowering the threshold trades false
   positives for sensitivity; that trade-off is a good viva discussion point.
