"""
End-to-end tests: run the real monitor.py as a subprocess.

These exercise the actual command line a user would type, not a re-implementation.
"""
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MONITOR = os.path.join(ROOT, "monitor.py")

FAILING = ("Oct  2 06:28:22 vm sshd[1503]: Failed password for {user} "
           "from {ip} port 52782 ssh2\n")


def run(args, **kw):
    return subprocess.run([sys.executable, MONITOR, *args],
                          capture_output=True, text=True, timeout=90, **kw)


@pytest.fixture
def cfg(tmp_path):
    """A settings.yaml whose alerts land in a temp folder."""
    alerts = tmp_path / "alerts"
    cfg_file = tmp_path / "settings.yaml"
    cfg_file.write_text(
        "check_interval_seconds: 1\n"
        f"alerts_dir: {alerts}\n"
        "thresholds:\n  failed_login_count: 5\n  failed_login_window_seconds: 180\n"
        "email:\n  enabled: false\ntelegram:\n  enabled: false\n",
        encoding="utf-8")
    return cfg_file, alerts


@pytest.fixture
def attack_log(tmp_path):
    log = tmp_path / "attack.log"
    users = ["root", "admin", "oracle", "test", "postgres", "guest"]
    log.write_text("".join(FAILING.format(user=u, ip="10.0.0.99") for u in users),
                   encoding="utf-8")
    return log


# ── the demo path ────────────────────────────────────────────
def test_replay_detects_the_attack_and_records_an_alert(cfg, attack_log):
    cfg_file, alerts = cfg
    proc = run(["--os", "linux", "--replay", str(attack_log),
                "--config", str(cfg_file), "--once"])

    assert proc.returncode == 0, proc.stderr
    assert "BRUTE-FORCE ATTACK DETECTED" in proc.stdout
    assert "10.0.0.99" in proc.stdout

    alert_file = alerts / "alerts.jsonl"
    assert alert_file.exists(), "the alert file is the evidence trail for the report"
    record = json.loads(alert_file.read_text(encoding="utf-8").strip())
    assert record["failure_count"] == 5
    assert record["source_ip"] == "10.0.0.99"
    assert "admin" in record["usernames"]


def test_replay_below_threshold_does_not_alert(cfg, tmp_path):
    cfg_file, alerts = cfg
    log = tmp_path / "quiet.log"
    log.write_text(FAILING.format(user="root", ip="10.0.0.99") * 3, encoding="utf-8")
    proc = run(["--os", "linux", "--replay", str(log),
                "--config", str(cfg_file), "--once"])
    assert proc.returncode == 0, proc.stderr
    assert "BRUTE-FORCE" not in proc.stdout
    assert not (alerts / "alerts.jsonl").exists()


def test_quiet_mode_hides_the_per_failure_line(cfg, attack_log):
    cfg_file, _ = cfg
    proc = run(["--os", "linux", "--replay", str(attack_log),
                "--config", str(cfg_file), "--once", "--quiet"])
    assert "in window" not in proc.stdout
    assert "BRUTE-FORCE ATTACK DETECTED" in proc.stdout


def test_config_is_found_from_any_working_directory(cfg, attack_log, tmp_path):
    """Regression: the config path used to be relative to the shell's cwd."""
    cfg_file, alerts = cfg
    proc = subprocess.run([sys.executable, MONITOR, "--os", "linux",
                           "--replay", str(attack_log), "--config", str(cfg_file), "--once"],
                          capture_output=True, text=True, timeout=90, cwd="/")
    assert proc.returncode == 0, proc.stderr
    assert "BRUTE-FORCE ATTACK DETECTED" in proc.stdout


# ── the CLI itself ───────────────────────────────────────────
def test_help_lists_the_new_options():
    proc = run(["--help"])
    assert proc.returncode == 0
    for flag in ("--gui", "--replay", "--test-alert", "--config", "--once"):
        assert flag in proc.stdout


def test_windows_mode_refuses_to_run_on_linux(cfg):
    if sys.platform == "win32":
        pytest.skip("this check is about non-Windows hosts")
    cfg_file, _ = cfg
    proc = run(["--os", "windows", "--config", str(cfg_file)])
    assert proc.returncode == 2
    assert "real Windows machine" in proc.stdout


def test_replay_of_a_missing_file_is_a_clear_error(cfg):
    cfg_file, _ = cfg
    proc = run(["--replay", "/does/not/exist.log", "--config", str(cfg_file)])
    assert proc.returncode == 1
    assert "Replay file not found" in proc.stdout


def test_test_alert_runs_without_crashing(cfg):
    cfg_file, alerts = cfg
    proc = run(["--test-alert", "--config", str(cfg_file)])
    assert proc.returncode == 0, proc.stderr
    assert "TEST ALERT" in proc.stdout
    assert (alerts / "alerts.jsonl").exists()
