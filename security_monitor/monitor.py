"""
===============================================================
  Lightweight Security Log Monitor
  Author : Pema Sherap Gurung (NP070051)
  Purpose: Final Year Project – SME Cybersecurity, Nepal
===============================================================

HOW TO RUN:
  Linux    →  sudo python3 monitor.py --os linux
  Windows  →  python monitor.py --os windows
  Web GUI  →  python3 monitor.py --os linux --gui
  Demo     →  python3 monitor.py --replay tests/logs/test_auth.log --gui
  Test     →  python3 monitor.py --test-alert
"""

import argparse
import os
import sys
import time
from collections import deque
from datetime import datetime

# Make "from modules..." work no matter which folder you started from.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from modules.linux_parser     import LinuxLogParser
from modules.threshold_engine import ThresholdEngine
from modules.alerter          import Alerter
from modules.config_loader    import load_config


# ─────────────────────────────────────────────────────────────
def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Lightweight Security Log Monitor for SMEs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  sudo python3 monitor.py --os linux\n"
            "  python3 monitor.py --os linux --gui\n"
            "  python3 monitor.py --replay tests/logs/test_auth.log --gui\n"
            "  python3 monitor.py --test-alert\n"
        ),
    )
    parser.add_argument("--os", choices=["linux", "windows", "auto"], default="auto",
                        help="Which operating system are you monitoring? (default: auto-detect)")
    parser.add_argument("--config", default=None,
                        help="Path to settings.yaml (default: config/settings.yaml next to this file)")
    parser.add_argument("--gui", action="store_true",
                        help="Also start the web dashboard (GUI)")
    parser.add_argument("--gui-host", default="0.0.0.0",
                        help="Address the dashboard listens on (default: 0.0.0.0)")
    parser.add_argument("--gui-port", type=int, default=8080,
                        help="Port for the dashboard (default: 8080, 0 = pick a free one)")
    parser.add_argument("--no-gui", action="store_true",
                        help="Never start the dashboard, even if config asks for it")
    parser.add_argument("--test-alert", action="store_true",
                        help="Send one test alert through every enabled channel, then exit")
    parser.add_argument("--replay", metavar="LOGFILE",
                        help="Replay an existing log file instead of tailing a live one "
                             "(great for demos – works on any OS)")
    parser.add_argument("--replay-delay", type=float, default=1.0,
                        help="Seconds between replayed events, so an audience can follow "
                             "(default: 1.0; ignored with --once)")
    parser.add_argument("--once", action="store_true",
                        help="Do a single pass over the log and exit (used by the tests)")
    parser.add_argument("--quiet", action="store_true",
                        help="Only print alerts, not every failed login")
    return parser


# ─────────────────────────────────────────────────────────────
class Monitor:
    """Wires the parser, the threshold engine, the alerter and the GUI together."""

    def __init__(self, args):
        self.args   = args
        self.config = load_config(args.config)

        self.project_root = os.path.dirname(self.config.get("_dir") or _HERE)
        alerts_dir = self.config.get("alerts_dir", "logs")
        if not os.path.isabs(alerts_dir):
            alerts_dir = os.path.join(self.project_root, alerts_dir)
        self.alerts_dir = alerts_dir

        self.alerter = Alerter(self.config, alerts_dir=alerts_dir)
        self.engine  = ThresholdEngine(self.config, verbose=not args.quiet)
        self.parser  = self._build_parser()

        self.recent_events = deque(maxlen=60)
        self.alerts        = deque(maxlen=20)
        self.started_at    = time.time()
        self.running       = False

    # ── setup ────────────────────────────────────────────────
    def _build_parser(self):
        os_choice = self.args.os
        if os_choice == "auto":
            os_choice = "windows" if sys.platform == "win32" else "linux"

        if self.args.replay:
            if not os.path.exists(self.args.replay):
                print(f"[ERROR] Replay file not found: {self.args.replay}")
                sys.exit(1)
            replay_cfg = {"linux": {"log_file": self.args.replay}}
            # replay from the top – we want the whole demo, not just new lines
            return LinuxLogParser(replay_cfg, from_start=True)

        if os_choice == "linux":
            return LinuxLogParser(self.config)

        # Windows
        if sys.platform != "win32":
            print("[ERROR] --os windows needs a real Windows machine.")
            print("        On Linux/macOS use --os linux, or demo with --replay.")
            sys.exit(2)
        from modules.windows_parser import WindowsLogParser
        parser = WindowsLogParser(self.config)
        if not parser._has_pywin32:          # pywin32 missing → nothing to read
            sys.exit(2)
        return parser

    def source_description(self) -> str:
        if self.args.replay:
            return f"replay: {os.path.basename(self.args.replay)}"
        if isinstance(self.parser, LinuxLogParser):
            return self.config["linux"]["log_file"]
        return "Windows Security Event Log"

    # ── state for the GUI ────────────────────────────────────
    def snapshot(self) -> dict:
        stats = self.engine.get_stats()
        return {
            "running":     self.running,
            "source":      self.source_description(),
            "started_at":  datetime.fromtimestamp(self.started_at).strftime("%Y-%m-%d %H:%M:%S"),
            "uptime":      _human_uptime(time.time() - self.started_at),
            "alert_channels": self.alerter.describe(),
            "counters": {
                "total_failures": self.engine.total_failures,
                "total_alerts":   self.engine.total_alerts,
                "last_alert":     (self.alerts[0]["detected_at"] if self.alerts else None),
            },
            "threshold":      stats,
            "alerts":         list(self.alerts),
            "recent_events":  list(self.recent_events),
        }

    # ── the main loop ────────────────────────────────────────
    def run(self):
        args = self.args

        print("[*] Starting Lightweight Security Log Monitor")
        print(f"[*] Watching : {self.source_description()}")
        print(f"[*] Alerts   : {self.alerter.describe()}")
        print(f"[*] Alert log: {os.path.join(self.alerts_dir, 'alerts.jsonl')}")

        dashboard = None
        if args.gui and not args.no_gui:
            from dashboard import Dashboard
            dashboard = Dashboard(self.snapshot, host=args.gui_host, port=args.gui_port)
            try:
                port = dashboard.start()
            except OSError as e:
                print(f"[ERROR] Could not start the dashboard: {e}")
                sys.exit(1)
            print(f"[*] Web GUI  : http://localhost:{port}   "
                  f"(on the network: http://<this-machine-ip>:{port})")

        print("[*] Press Ctrl+C to stop.\n")

        self.running = True
        replay_gap = args.replay_delay if (args.replay and not args.once) else 0
        try:
            while self.running:
                events = self.parser.get_new_events()

                for event in events:
                    self._handle(event)
                    if args.replay and replay_gap:
                        time.sleep(replay_gap)     # let the audience follow along

                if args.once:
                    break

                if args.replay and not events:
                    print("\n[*] Replay finished – the monitor keeps running for the GUI. "
                          "Ctrl+C to stop.")
                    args.replay = None            # stop re-reading the file
                    self._switch_to_idle()

                time.sleep(self.config.get("check_interval_seconds", 10))

        except KeyboardInterrupt:
            print("\n[*] Monitor stopped by user.")
        finally:
            self.running = False
            if dashboard is not None:
                dashboard.stop()
            if hasattr(self.parser, "close"):
                self.parser.close()

    # ── helpers ──────────────────────────────────────────────
    def _handle(self, event: dict):
        self.recent_events.appendleft({
            "at":        datetime.now().strftime("%H:%M:%S"),
            "source_ip": event.get("source_ip", "?"),
            "username":  event.get("username", "?"),
            "os":        event.get("os", "?"),
        })

        alert = self.engine.process_event(event)
        if alert:
            print(f"[!] ALERT: {alert['message']}")
            self.alerts.appendleft(alert)
            try:
                self.alerter.send(alert)
            except Exception as e:               # never let alerting kill the monitor
                print(f"  [ERROR] Alerting failed: {e}")

    def _switch_to_idle(self):
        """After a replay, idle instead of hammering the (finished) file."""
        class _Idle:
            def get_new_events(self):
                return []
        self.parser = _Idle()


def _human_uptime(seconds: float) -> str:
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m}m"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


# ─────────────────────────────────────────────────────────────
def main():
    args = build_arg_parser().parse_args()

    # --test-alert: check the plumbing, then stop.
    if args.test_alert:
        config = load_config(args.config)
        project_root = os.path.dirname(config.get("_dir") or _HERE)
        alerts_dir = config.get("alerts_dir", "logs")
        if not os.path.isabs(alerts_dir):
            alerts_dir = os.path.join(project_root, alerts_dir)
        Alerter(config, alerts_dir=alerts_dir).send_test()
        return

    Monitor(args).run()


if __name__ == "__main__":
    main()
