# Lightweight Security Log Monitor
### Final Year Project – Pema Sherap Gurung (NP070051)
**CT098-3-2-RMCT | Technology Park Malaysia**

---

## What This Does
Monitors Linux and Windows server logs for brute-force attacks.
Sends real-time alerts via **Email** and **Telegram**.

---

## Project Structure
```
security_monitor/
├── monitor.py                ← MAIN script (run this)
├── requirements.txt          ← Python libraries needed
├── config/
│   └── settings.yaml         ← YOUR settings (edit this first!)
├── modules/
│   ├── linux_parser.py       ← Reads /var/log/auth.log
│   ├── windows_parser.py     ← Reads Windows Event Log
│   ├── threshold_engine.py   ← Detects attack patterns
│   ├── alerter.py            ← Sends Email + Telegram alerts
│   └── config_loader.py      ← Reads settings.yaml
├── tests/
│   └── simulate_attack.py    ← Fake attack for testing
└── logs/
    └── test_auth.log         ← Created during testing
```

---

## Setup (Step-by-Step)

### Step 1 – Install Python
Download Python 3.10+ from https://python.org

### Step 2 – Install dependencies
Open a terminal in this folder and run:
```bash
pip install -r requirements.txt
```

### Step 3 – Configure your settings
Edit `config/settings.yaml`:
- Set your Gmail address and App Password
- Set your Telegram Bot token and Chat ID
- Set the correct log file path for your Linux system

### Step 4 – Test it works (without a real attack)
In Terminal 1, change the log_file in settings.yaml to:
  `log_file: logs/test_auth.log`

Then run the monitor:
```bash
python3 monitor.py --os linux
```

In Terminal 2, run the simulator:
```bash
python3 tests/simulate_attack.py
```

Watch Terminal 1 – after 5 failures you should see an alert!

### Step 5 – Run on a real Linux server
Change log_file back to `/var/log/auth.log` then:
```bash
sudo python3 monitor.py --os linux
```

### Step 6 – Run on Windows
```bash
python monitor.py --os windows
```
(Must be run as Administrator)

---

## How It Works
1. The script reads new lines from the log file every 10 seconds
2. Each line is parsed with regex to extract IP address and username
3. The threshold engine counts failures per IP within a 3-minute window
4. If an IP exceeds 5 failures → alert is sent via Email + Telegram
5. The alert includes the attacker's IP, failure count, and timestamp

---

## References
- Lopez et al. (2020) – Intelligent Detection and Recovery from Cyberattacks for SMEs
- Haakila (2022) – Implementing Security Monitoring at SMBs
- Mercer (2013) – SIEM for Small and Medium-Sized Enterprises
