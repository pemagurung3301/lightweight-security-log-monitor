# How to showcase this project

## The short answer: CLI **and** GUI — CLI is the product, GUI is the lens

**Demonstrate the CLI first, then open the GUI.** They are not alternatives:

- The **CLI** *is* the deliverable. It proves the pipeline works: real log file
  → parser → threshold engine → alert. An examiner can read every line on the
  screen and match it to your code. If only one thing can be shown, show this.
- The **GUI** (`--gui`) is a read-only dashboard over the same engine. It is the
  part a non-technical audience (or an SME owner) understands in two seconds,
  and it is what makes the project look finished. It adds **no new dependency** —
  `dashboard.py` is standard-library only, which is worth saying out loud given
  the "lightweight" in the title.

Recommended flow for a 10-minute demo: **2 min CLI → 4 min live attack with the
GUI open → 2 min alert arriving (email/Telegram) → 2 min questions**.

---

## 1. Pre-flight checklist (do this the day before, and again 30 min before)

```bash
cd security_monitor
python3 -m pytest tests/ -q            # expect: 53 passed
python3 monitor.py --test-alert        # checks email/Telegram plumbing
bash vm_setup_scripts/6_demo.sh        # rehearse the exact demo you will give
```

- [ ] `pytest` green
- [ ] `--test-alert` reaches your inbox **and** your Telegram
- [ ] You know your VM's IP (`hostname -I`) and it is reachable from your laptop
- [ ] Laptop and VM on the **same** network (university Wi-Fi often blocks
      client-to-client traffic — test this in advance, or use a phone hotspot)
- [ ] Browser window ready for the GUI, terminal font zoomed to ~18 pt for the
      projector
- [ ] A recording of a successful run on your phone as a fallback
- [ ] `logs/alerts.jsonl` from a previous run, to show the evidence file

---

## 2. Demo A — the safe one-command demo (works on any machine)

No SSH server, no internet, no VM, no credentials. Use this if the network fails,
or as your opening act.

```bash
cd security_monitor
bash vm_setup_scripts/6_demo.sh        # then open http://localhost:8080
```

What happens: a fake attacker writes real-format sshd lines into
`logs/demo_auth.log`; the monitor tails that file and the dashboard fills up.
A new attacker IP appears every ~20 s, so the screen is never static.

**What to say:** *"This is the whole detection pipeline running against a log
file in the OpenSSH format. Nothing is hard-coded — the same binary reads
`/var/log/auth.log` in production; I have only changed the path in the config."*

Equivalent manual form, if you prefer two terminals:

```bash
# terminal 1
python3 monitor.py --os linux --config config/settings_demo.yaml --gui
# terminal 2
python3 tests/simulate_attack.py --log logs/demo_auth.log --loop --delay 2
```

---

## 3. Demo B — CLI, the core of the project

Two terminals, side by side. This is the one to rehearse most.

```bash
# TERMINAL 1 – the monitor
cd security_monitor
sudo python3 -u monitor.py --os linux          # sudo: auth.log is root-readable
```

```bash
# TERMINAL 2 – the attack (from your laptop, against the VM)
bash vm_setup_scripts/4_simulate_brute_force.sh 192.168.1.105
```

Terminal 1 will show:

```
[*] Threshold engine ready:
    Rule: alert on 5 or more failures in 180s from the same IP (re-alert after 300s)
[*] Watching : /var/log/auth.log
[*] Alerts   : email→you@gmail.com, telegram→123456789, local alert file

  [2026-10-02 14:02:11] Failed login from 192.168.1.20 (username: root) – 1/5 in window
  [2026-10-02 14:02:12] Failed login from 192.168.1.20 (username: root) – 2/5 in window
  ...
  [2026-10-02 14:02:16] Failed login from 192.168.1.20 (username: root) – 5/5 in window
[!] ALERT: 🚨 BRUTE-FORCE ATTACK DETECTED
IP Address : 192.168.1.20
Failures   : 5 in 180 seconds
Usernames  : root
OS         : linux
Detected at: 2026-10-02 14:02:16
  [✓] Email alert sent to you@gmail.com
  [✓] Telegram alert sent to chat 123456789
```

**The three things to point at, in order:**
1. The counter climbing `1/5 … 5/5` — this *is* the sliding-window algorithm.
2. The alert firing on the **5th**, not the 50th, failure — latency matters in
   incident response.
3. Only **one** alert for the whole attack (the 6th, 7th, 8th failures print but
   do not re-alert) — that is the cooldown, and it is the difference between a
   usable tool and an inbox full of spam.

Then show the evidence file:

```bash
cat logs/alerts.jsonl | python3 -m json.tool
```

---

## 4. Demo C — the GUI

Start the monitor with `--gui` (any of the demos above accept it) and open
`http://localhost:8080`.

To show it from a second machine — often the most impressive moment, because the
examiner sees their own laptop become the "security console":

```bash
python3 monitor.py --os linux --gui        # listens on 0.0.0.0:8080
# then, on another device on the same network:
#   http://<ip-of-the-monitored-machine>:8080
```

Walk the screen top-left to bottom-right:
1. **Header pills** — what is being watched, the rule, which alert channels are live.
2. **Counters** — failures seen, alerts fired, distinct IPs, uptime.
3. **Attackers table** — one row per source IP with a progress bar that turns red
   when the threshold is breached, plus every username that IP tried.
4. **Alert feed** — the exact message that was emailed/messaged.
5. **Live events** — the raw tail, so the GUI can be tied back to the log file.

**If asked "why a web GUI and not a desktop app?"** — a browser-based dashboard
needs no installation on the viewing machine, works from a phone, can be
projected from anywhere on the LAN, and keeps the monitored server headless.
That is exactly what an SME without an IT department needs.

---

## 5. Demo D — real machine, real attack (the strongest version)

This is the one to put in the report and, if time allows, to present live.

### On the Ubuntu VM (inside the VM)
```bash
sudo apt install -y git
git clone <your-repo-url> && cd lightweight-security-log-monitor/security_monitor

bash vm_setup_scripts/1_install_dependencies.sh    # python3 + pyyaml
bash vm_setup_scripts/2_enable_ssh.sh              # sshd + finds the auth log
nano config/settings.yaml                          # log_file + alert credentials
bash vm_setup_scripts/3_run_monitor.sh --gui       # monitor + dashboard
```

### On your laptop (outside the VM)
```bash
sudo apt install -y hydra
bash vm_setup_scripts/4_simulate_brute_force.sh <VM_IP>
```

### Back inside the VM
```bash
bash vm_setup_scripts/5_check_logs.sh              # prove the log really recorded it
```

Notes that are easy to get wrong on the day:

- **`sudo` is required** — `/var/log/auth.log` is mode `640 root:adm`. Without it
  the monitor prints `Permission denied` and looks broken.
- **Do not disable `PermitRootLogin`.** Tested: with Ubuntu's default
  `PermitRootLogin prohibit-password`, a password attempt for root still writes
  `Failed password for root from …`, so the demo works untouched.
- **hydra must run on a different machine than the VM**, otherwise the source IP
  is `127.0.0.1` and the demo looks like the machine attacking itself.
- **No hydra, or a locked-down network?** `python3 tests/simulate_attack.py`
  inside the VM writes the same log lines sshd would. Say plainly that this is
  a simulation and show the real run in your recording.

### On a Windows machine (verify before you present)
```powershell
pip install -r requirements.txt        # installs pywin32 automatically
# Start → "PowerShell" → Run as administrator   (reading the Security log needs it)
python monitor.py --os windows --gui
```
Then cause real failed logons: `runas /user:doesnotexist cmd`, or an RDP login
with a wrong password from another machine (Event ID 4625, Logon Type 10).
⚠️ The Windows path could not be executed in the review environment — see
`docs/AUDIT.md` §2.5. **Test it, and if `StringInserts` comes back empty the
message-parsing fallback should still fill in the IP; check the printed
`ip=` value in the event line before you rely on it.**

---

## 6. Recording it for the report

```bash
# terminal recorder (nice, small files):
sudo apt install -y asciinema && asciinema rec demo.cast
# …run Demo B… then Ctrl-D, and upload demo.cast or convert it:
#   agg demo.cast demo.gif

# GUI screenshots: capture (a) empty dashboard, (b) mid-attack with the bar
# climbing, (c) the moment the row turns red, (d) the Telegram/email alert
# side by side with the dashboard. Four images tell the whole story.
```

---

## 7. Likely viva questions, and the answers this code actually supports

**"How do you avoid re-sending an alert for every failed attempt?"**
An alert sets a cooldown for that IP (`alert_cooldown_seconds`, default 300 s).
Failures keep being counted and printed; only the notification is suppressed.

**"Why 5 failures in 180 seconds?"**
A configurable starting point, not a derived constant. It matches the guidance in
the literature (Lopez et al. 2020; Haakila 2022) that SMEs need a low-noise rule.
Trade-off: lower = more false positives from a mistyping user, higher = slower
detection. Both values are in `settings.yaml` precisely so an SME can tune them.

**"What happens when the log file rotates at midnight?"**
The parser tracks the file's inode and size and resets its offset when either
changes. (This was a real bug in the first version — `docs/AUDIT.md` §2.4 — which
is a good thing to be able to talk about.)

**"What does it cost to run?"**
One Python process, one dependency (`pyyaml`), polling every 10 s, no database,
no agents, no cloud. Memory is bounded because stale IPs are swept out of the
counter. That is the whole point of "lightweight" for an SME.

**"What can't it do?"**
It does not block the attacker, does not correlate across machines, and only
watches failed SSH logins on Linux / Event 4625 on Windows. See
`docs/AUDIT.md` §6 — naming your own limitations is worth more marks than
over-claiming.

**"How did you test it?"**
53 automated tests, including one that runs the real `monitor.py` as a
subprocess and asserts on its output and on `logs/alerts.jsonl`; plus a
verification against a live OpenSSH server producing genuine
`Failed password` lines. `python3 -m pytest tests/ -q`.
