# Lightweight Security Log Monitor
### Final Year Project – Pema Sherap Gurung

Watches Linux (`/var/log/auth.log`) and Windows (Security Event Log, ID 4625)
for **SSH / logon brute-force attacks** and sends real-time alerts by
**Email**, **Telegram**, and to a local JSON evidence file.

One Python process, one dependency (`pyyaml`), no database, no agents, no cloud —
deliberately small enough for a small business to run and understand.

---

## Status

- **53 automated tests pass** — `python3 -m pytest tests/ -q`
- End-to-end verified against a **live OpenSSH server** producing real
  `Failed password` log lines (5 real failures → alert in 2 s)
- Verified against the Windows Event 4625 field layout
- The Windows code path could not be executed in the review environment
  (Linux only) — see `docs/AUDIT.md` §2.5

**`docs/AUDIT.md`** — the full code review: **19 defects** in the first
version, each one reproduced with the command that shows it, and what was changed.
**`docs/SHOWCASE.md`** — how to demonstrate this on a real machine, CLI and GUI.

---

## Quick start (60 seconds, no server needed)

```bash
cd security_monitor
pip install -r requirements.txt
bash vm_setup_scripts/6_demo.sh          # then open http://localhost:8080
```

That runs a fake attacker against a demo log file and starts both the terminal
monitor and the web dashboard. Nothing is sent anywhere.

---

## Running it for real

### Linux
```bash
cd security_monitor
pip install -r requirements.txt
nano config/settings.yaml                # log_file + alert credentials
sudo python3 -u monitor.py --os linux    # sudo: auth.log is root-readable
```

### Windows (run the terminal as Administrator)
```powershell
pip install -r requirements.txt          # installs pywin32 automatically
python monitor.py --os windows --gui
```

### Every option
```bash
python3 monitor.py --help
```

| Flag | What it does |
|------|--------------|
| `--os linux\|windows\|auto` | Which log source to read (default: auto-detect) |
| `--config PATH` | Use a different `settings.yaml` |
| `--gui` | Start the web dashboard (default `0.0.0.0:8080`) |
| `--gui-port N` | Dashboard port (`0` = pick a free one) |
| `--replay FILE` | Replay a log file instead of tailing a live one |
| `--replay-delay S` | Seconds between replayed events (default 1) |
| `--test-alert` | Send one test alert through every channel, then exit |
| `--once` | One pass and exit (used by the tests) |
| `--quiet` | Print alerts only, not every failed login |

---

## Showing it to people

**Terminal 1 — the monitor**
```bash
sudo python3 -u monitor.py --os linux --gui
```
**Terminal 2 — the attack** (from another machine, against the monitored one)
```bash
bash vm_setup_scripts/4_simulate_brute_force.sh <TARGET_IP>
```
No attacker tool? `python3 tests/simulate_attack.py` writes the same log lines
sshd would, or `python3 monitor.py --replay tests/logs/test_auth.log` replays a
recorded attack on any operating system.

What the screen shows:
```
  [14:02:11] Failed login from 192.168.1.20 (username: root) – 1/5 in window
  [14:02:12] Failed login from 192.168.1.20 (username: root) – 2/5 in window
  ...
  [14:02:16] Failed login from 192.168.1.20 (username: root) – 5/5 in window
[!] ALERT: 🚨 BRUTE-FORCE ATTACK DETECTED
IP Address : 192.168.1.20
Failures   : 5 in 180 seconds
Usernames  : root
  [✓] Email alert sent to you@gmail.com
  [✓] Telegram alert sent to chat 123456789
```

Full demo scripts, a viva question list and a pre-flight checklist are in
**[`docs/SHOWCASE.md`](docs/SHOWCASE.md)**.

---

## Configuration — `config/settings.yaml`

```yaml
check_interval_seconds: 10      # how often to check the log
alerts_dir: logs                # alerts.jsonl is written here

linux:
  log_file: /var/log/auth.log   # CentOS/RHEL: /var/log/secure

thresholds:
  failed_login_count: 5             # failures that trigger an alert
  failed_login_window_seconds: 180  # …counted within this many seconds
  alert_cooldown_seconds: 300       # silence per IP after an alert

email:    { enabled: false, smtp_server: smtp.gmail.com, smtp_port: 587, ... }
telegram: { enabled: false, ... }
```

### 🔑 Keep your secrets out of Git
Environment variables override the YAML file, so the file can stay in the repo:

```bash
export SMTP_PASSWORD='xxxx xxxx xxxx xxxx'   # Gmail App Password
export TELEGRAM_BOT_TOKEN='123456:ABC...'
export TELEGRAM_CHAT_ID='123456789'
```

- Gmail App Password: Google Account → Security → 2-Step Verification → *App passwords*
- Telegram: `@BotFather` → `/newbot` → copy the token; message your bot, then open
  `https://api.telegram.org/bot<TOKEN>/getUpdates` and read `"chat":{"id":…}`
- Check it works: `python3 monitor.py --test-alert`

---

## How it works

```
 /var/log/auth.log ─┐
                    ├─► parser ──► threshold engine ──► alerter ──► email
 Windows Security ──┘   (regex)     (sliding window)     │        └─► Telegram
   log, Event 4625                                      └────────► alerts.jsonl
                                        └────────────► dashboard (--gui)
```

1. The log file is **tailed** — only new bytes are read, every
   `check_interval_seconds`. Rotation and truncation are detected so the monitor
   never goes blind.
2. Each line is matched against a regex to pull out the **username** and **source
   IP** (IPv4 and IPv6). Only `Failed password` lines are counted — a real
   OpenSSH server writes exactly one of those per rejected password, and counting
   the surrounding `Invalid user` / `Connection closed` lines too would inflate
   the counter and fire early.
3. The **threshold engine** keeps a sliding window of timestamps per IP and
   alerts when the count reaches `failed_login_count`.
4. The **alerter** sends the alert and appends it to `logs/alerts.jsonl`.
   A failing channel is reported, never fatal.
5. With `--gui`, the engine's live state is served as a small web dashboard.

---

## Project structure

```
lightweight-security-log-monitor/
├── README.md                     ← you are here
├── .gitignore
├── docs/
│   ├── AUDIT.md                  ← code review: bugs found + fixes
│   └── SHOWCASE.md               ← how to demo it (CLI + GUI, viva Q&A)
└── security_monitor/
    ├── monitor.py                ← MAIN script (run this)
    ├── dashboard.py              ← web GUI (standard library only)
    ├── requirements.txt
    ├── config/
    │   ├── settings.yaml         ← YOUR settings (edit this)
    │   └── settings_demo.yaml    ← safe config used by the demo
    ├── modules/
    │   ├── linux_parser.py       ← tails /var/log/auth.log
    │   ├── windows_parser.py     ← reads Windows Event Log (4625)
    │   ├── threshold_engine.py   ← the detection brain
    │   ├── alerter.py            ← email + Telegram + alerts.jsonl
    │   └── config_loader.py      ← reads settings.yaml
    ├── tests/
    │   ├── test_*.py             ← 53 pytest tests
    │   ├── simulate_attack.py    ← fake attack for demos
    │   └── logs/test_auth.log    ← recorded attack, for --replay
    ├── logs/                     ← alerts.jsonl lands here (gitignored)
    └── vm_setup_scripts/         ← numbered setup + demo scripts
```

---

## Tests

```bash
cd security_monitor
pip install pytest
python3 -m pytest tests/ -q          # 53 passed
```

They cover the parser against real sshd output (IPv6, rotation, truncation,
binary junk, partial lines), the sliding window (firing, expiry, cooldown,
memory sweep), the alerter (misconfiguration, escaping, no-crash guarantees),
the dashboard endpoints, and the real `monitor.py` command line end to end.

---

## Known limitations

Detection is notification-only (no automated blocking), threshold-based (an
attacker who stays just under the limit is invisible), and scoped to SSH on
Linux / Event 4625 on Windows. The full list, with reasoning, is in
`docs/AUDIT.md` §6.

---

## References
- Lopez et al. (2020) – Intelligent Detection and Recovery from Cyberattacks for SMEs
- Haakila (2022) – Implementing Security Monitoring at SMBs
- Mercer (2013) – SIEM for Small and Medium-Sized Enterprises
