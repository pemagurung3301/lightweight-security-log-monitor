"""Tests for modules/alerter.py and modules/config_loader.py"""
import json
import urllib.parse

import pytest

from modules.alerter import Alerter
from modules.config_loader import load_config, DEFAULTS

ALERT = {"type": "brute_force_detected", "source_ip": "1.2.3.4",
         "failure_count": 5, "message": "boom", "detected_at": "2026-10-02 06:00:00"}


# ── alerter: must never crash ────────────────────────────────
def test_missing_email_fields_do_not_crash(tmp_path):
    """Regression: cfg['sender_email'] raised KeyError and killed the monitor."""
    alerter = Alerter({"email": {"enabled": True, "smtp_server": "x", "smtp_port": 587,
                                 "recipient_email": "a@b.c"}},
                      alerts_dir=str(tmp_path))
    alerter.send(ALERT)                                    # must not raise
    assert alerter.last_result["email"] == "misconfigured"


def test_placeholder_password_is_refused(tmp_path):
    alerter = Alerter({"email": {"enabled": True, "sender_email": "me@gmail.com",
                                 "sender_password": "YOUR_APP_PASSWORD",
                                 "recipient_email": "a@b.c"}},
                      alerts_dir=str(tmp_path))
    alerter.send(ALERT)
    assert alerter.last_result["email"] == "placeholder password"


def test_placeholder_telegram_token_is_refused(tmp_path):
    alerter = Alerter({"telegram": {"enabled": True, "bot_token": "YOUR_BOT_TOKEN",
                                    "chat_id": "YOUR_CHAT_ID"}},
                      alerts_dir=str(tmp_path))
    alerter.send(ALERT)
    assert alerter.last_result["telegram"] == "misconfigured"


def test_disabled_channels_are_reported_as_dry_run(tmp_path, capsys):
    Alerter({}, alerts_dir=str(tmp_path)).send(ALERT)
    assert "dry-run" in capsys.readouterr().out


# ── alerter: the local alert file ────────────────────────────
def test_alert_is_written_to_the_alert_file(tmp_path):
    Alerter({}, alerts_dir=str(tmp_path)).send(ALERT)
    lines = (tmp_path / "alerts.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["source_ip"] == "1.2.3.4"
    assert "recorded_at" in record


# ── alerter: telegram payload ────────────────────────────────
def test_telegram_payload_escapes_html(tmp_path, monkeypatch):
    """Usernames come from the log file, so an attacker can put '<' or '&' in
    them. Unescaped, the Telegram API answers HTTP 400 and the alert is lost."""
    captured = {}

    class FakeResponse:
        def read(self):
            return b'{"ok": true}'

    def fake_urlopen(req, timeout=None):
        captured["body"] = req.data.decode()
        captured["url"] = req.full_url
        return FakeResponse()

    monkeypatch.setattr("modules.alerter.urllib.request.urlopen", fake_urlopen)

    alerter = Alerter({"telegram": {"enabled": True, "bot_token": "123:ABC",
                                    "chat_id": "42"}}, alerts_dir=None)
    alerter.send({"message": "user <b>&</b> attacked", "source_ip": "1.2.3.4"})

    assert captured["url"].endswith("/bot123:ABC/sendMessage")
    fields = urllib.parse.parse_qs(captured["body"])
    assert fields["chat_id"] == ["42"]
    assert fields["parse_mode"] == ["HTML"]
    assert "&lt;b&gt;" in fields["text"][0]          # escaped, not raw HTML


def test_telegram_failure_is_reported_not_raised(monkeypatch):
    def boom(req, timeout=None):
        raise OSError("no internet")

    monkeypatch.setattr("modules.alerter.urllib.request.urlopen", boom)
    alerter = Alerter({"telegram": {"enabled": True, "bot_token": "1:2",
                                    "chat_id": "42"}}, alerts_dir=None)
    alerter.send({"message": "x"})                   # must not raise
    assert alerter.last_result["telegram"].startswith("error:")


def test_describe_lists_active_channels(tmp_path):
    alerter = Alerter({"email": {"enabled": True, "recipient_email": "a@b.c",
                                 "sender_email": "me@x.com", "sender_password": "pw"},
                       "telegram": {"enabled": True, "bot_token": "1:2", "chat_id": "9"}},
                      alerts_dir=str(tmp_path))
    text = alerter.describe()
    assert "email" in text and "telegram" in text and "alert file" in text


# ── config loader ────────────────────────────────────────────
def test_defaults_fill_in_missing_keys(tmp_path):
    cfg_file = tmp_path / "settings.yaml"
    cfg_file.write_text("linux:\n  log_file: /tmp/x.log\n", encoding="utf-8")
    config = load_config(str(cfg_file))
    assert config["linux"]["log_file"] == "/tmp/x.log"
    assert config["check_interval_seconds"] == DEFAULTS["check_interval_seconds"]
    assert config["thresholds"]["failed_login_count"] == 5
    assert config["email"]["enabled"] is False


def test_user_values_win_over_defaults(tmp_path):
    cfg_file = tmp_path / "settings.yaml"
    cfg_file.write_text("check_interval_seconds: 3\nthresholds:\n  failed_login_count: 9\n",
                        encoding="utf-8")
    config = load_config(str(cfg_file))
    assert config["check_interval_seconds"] == 3
    assert config["thresholds"]["failed_login_count"] == 9
    assert config["thresholds"]["failed_login_window_seconds"] == 180   # untouched


def test_missing_config_file_exits(tmp_path):
    with pytest.raises(SystemExit):
        load_config(str(tmp_path / "nope.yaml"))


def test_broken_yaml_exits_with_a_message(tmp_path):
    cfg_file = tmp_path / "settings.yaml"
    cfg_file.write_text("a: [1, 2\nb: : :\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        load_config(str(cfg_file))
