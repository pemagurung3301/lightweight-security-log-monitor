"""
alerter.py
──────────
Sends security alerts via three channels:
  1. Email    (using Gmail's SMTP server)
  2. Telegram (using a Telegram Bot)
  3. Local alert file (always on – gives you a written record for the report)

KEY CONCEPTS:
  SMTP = Simple Mail Transfer Protocol (how email gets sent)
  API  = Application Programming Interface
         (Telegram gives us a URL we can call to send a message)

SECRETS: never commit your password/token. The alerter reads these
environment variables first, so the YAML file can stay in Git safely:
    SMTP_PASSWORD        – Gmail App Password
    TELEGRAM_BOT_TOKEN   – token from @BotFather
"""

import html                             # escapes text before we send HTML
import json
import os
import smtplib                          # built-in Python email library
import urllib.request                   # built-in Python HTTP library
import urllib.parse
import ssl
from email.mime.text    import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

# Placeholders that mean "the user has not filled this in yet"
_PLACEHOLDERS = {"", "YOUR_APP_PASSWORD", "YOUR_BOT_TOKEN", "YOUR_CHAT_ID",
                 "YOUR_EMAIL@gmail.com", "CHANGE_ME"}


class Alerter:
    """
    Sends alerts via Email and/or Telegram.
    Which channels are used depends on what is enabled in settings.yaml.

    A broken or half-configured channel must never crash the monitor –
    an earlier version raised KeyError here and took the whole process down.
    """

    def __init__(self, config: dict, alerts_dir: str | None = None):
        self.email_cfg    = dict(config.get("email",    {}) or {})
        self.telegram_cfg = dict(config.get("telegram", {}) or {})

        # environment variables win over the YAML file
        if os.environ.get("SMTP_PASSWORD"):
            self.email_cfg["sender_password"] = os.environ["SMTP_PASSWORD"]
        if os.environ.get("TELEGRAM_BOT_TOKEN"):
            self.telegram_cfg["bot_token"] = os.environ["TELEGRAM_BOT_TOKEN"]
        if os.environ.get("TELEGRAM_CHAT_ID"):
            self.telegram_cfg["chat_id"] = os.environ["TELEGRAM_CHAT_ID"]

        self.alerts_dir = alerts_dir
        self.last_result = {"email": "disabled", "telegram": "disabled",
                            "file": "off"}
        self._warned = set()

    # ── public API ───────────────────────────────────────────
    def send(self, alert: dict):
        """
        Send an alert through every enabled channel.
        This is the only method you need to call from outside.
        Never raises – an alerting problem is reported, not thrown.
        """
        message = alert.get("message", "Security alert triggered.")

        if self.email_cfg.get("enabled", False):
            self._send_email(alert, message)

        if self.telegram_cfg.get("enabled", False):
            self._send_telegram(message)

        self._write_alert_file(alert)

        if not self.email_cfg.get("enabled") and not self.telegram_cfg.get("enabled"):
            print("  [i] No remote channel enabled – alert recorded locally only (dry-run).")

    def send_test(self) -> None:
        """Send a 'hello, this works' alert. Used by: monitor.py --test-alert"""
        test_alert = {
            "type":          "test_alert",
            "source_ip":     "127.0.0.1",
            "failure_count": 0,
            "window_secs":   0,
            "os":            "test",
            "last_username": "test",
            "usernames":     ["test"],
            "detected_at":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "message":       ("✅ TEST ALERT from Lightweight Security Log Monitor\n"
                              "If you can read this, your alert channel works."),
        }
        print("[*] Sending test alert through every enabled channel...")
        print(f"[*] Channels: {self.describe()}")
        self.send(test_alert)
        print("\n" + test_alert["message"])

    def describe(self) -> str:
        """One-line summary of what will actually happen when an alert fires."""
        channels = []
        if self.email_cfg.get("enabled"):
            channels.append(f"email→{self.email_cfg.get('recipient_email', '?')}")
        if self.telegram_cfg.get("enabled"):
            channels.append(f"telegram→{self.telegram_cfg.get('chat_id', '?')}")
        if self.alerts_dir:
            channels.append("local alert file")
        return ", ".join(channels) if channels else "none (dry-run)"

    # ── EMAIL ────────────────────────────────────────────────
    def _send_email(self, alert: dict, message: str):
        """
        Send an alert email using Gmail SMTP.

        SETUP STEPS (do this once):
        1. Go to your Google Account → Security → 2-Step Verification (turn on)
        2. Search for "App passwords" in Google Account settings
        3. Create an App Password for "Mail"
        4. Put it in settings.yaml, or better:  export SMTP_PASSWORD='xxxx xxxx xxxx xxxx'
        """
        cfg = self.email_cfg
        try:
            sender    = str(cfg["sender_email"])
            password  = str(cfg["sender_password"])
            recipient = str(cfg["recipient_email"])
        except KeyError as e:
            self.last_result["email"] = "misconfigured"
            print(f"  [ERROR] Email is enabled but {e} is missing in settings.yaml")
            return

        if password in _PLACEHOLDERS:
            self.last_result["email"] = "placeholder password"
            print("  [ERROR] Email sender_password is still a placeholder "
                  "(use a Gmail App Password, or set SMTP_PASSWORD).")
            return

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[SECURITY ALERT] Brute-Force Detected – {alert.get('source_ip', '?')}"
        msg["From"]    = sender
        msg["To"]      = recipient

        body = (
            f"Security Alert from your Log Monitor\n"
            f"{'=' * 40}\n\n"
            f"{message}\n\n"
            f"{'=' * 40}\n"
            f"Sent by: Lightweight SME Security Monitor\n"
            f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        )
        msg.attach(MIMEText(body, "plain"))

        try:
            context = ssl.create_default_context()
            # timeout=20 stops a dead SMTP server from hanging the monitor forever
            with smtplib.SMTP(cfg.get("smtp_server", "smtp.gmail.com"),
                              int(cfg.get("smtp_port", 587)), timeout=20) as server:
                server.ehlo()
                server.starttls(context=context)       # encrypt the connection
                server.login(sender, password)
                server.sendmail(sender, recipient, msg.as_string())

            self.last_result["email"] = "sent"
            print(f"  [✓] Email alert sent to {recipient}")

        except smtplib.SMTPAuthenticationError:
            self.last_result["email"] = "auth failed"
            print("  [ERROR] Email login failed. Check your Gmail App Password "
                  "(settings.yaml or SMTP_PASSWORD).")
        except Exception as e:
            self.last_result["email"] = f"error: {e}"
            print(f"  [ERROR] Failed to send email: {e}")

    # ── TELEGRAM ─────────────────────────────────────────────
    def _send_telegram(self, message: str):
        """
        Send an alert to a Telegram chat using a Bot.

        SETUP STEPS (do this once):
        1. Open Telegram → search for "@BotFather"
        2. Send /newbot → follow instructions → copy the token
        3. Send a message to your new bot
        4. Visit: https://api.telegram.org/bot<TOKEN>/getUpdates
           and copy the "chat":{"id": ...} number
        5. Put both in settings.yaml, or better:
           export TELEGRAM_BOT_TOKEN='...'   TELEGRAM_CHAT_ID='...'
        """
        cfg     = self.telegram_cfg
        token   = str(cfg.get("bot_token", "") or "")
        chat_id = str(cfg.get("chat_id",   "") or "")

        if not token or not chat_id or token in _PLACEHOLDERS or chat_id in _PLACEHOLDERS:
            self.last_result["telegram"] = "misconfigured"
            print("  [ERROR] Telegram is enabled but bot_token/chat_id are empty "
                  "or still placeholders in settings.yaml")
            return

        url = f"https://api.telegram.org/bot{token}/sendMessage"

        # We send with parse_mode=HTML so the alert is easy to read, therefore
        # every dynamic value has to be escaped first. Usernames come straight
        # out of the log file (an attacker controls them) – an unescaped "<" or
        # "&" makes the Telegram API reject the message with HTTP 400.
        safe_message = html.escape(message).replace("\n", "\n")
        data = urllib.parse.urlencode({
            "chat_id":    chat_id,
            "text":       f"<pre>{safe_message}</pre>",
            "parse_mode": "HTML",
        }).encode("utf-8")

        try:
            req      = urllib.request.Request(url, data=data, method="POST")
            response = urllib.request.urlopen(req, timeout=15)
            result   = json.loads(response.read().decode("utf-8"))

            if result.get("ok"):
                self.last_result["telegram"] = "sent"
                print(f"  [✓] Telegram alert sent to chat {chat_id}")
            else:
                self.last_result["telegram"] = f"api error: {result.get('description')}"
                print(f"  [ERROR] Telegram API error: {result}")

        except Exception as e:
            self.last_result["telegram"] = f"error: {e}"
            print(f"  [ERROR] Failed to send Telegram message: {e}")

    # ── LOCAL FILE (always on) ───────────────────────────────
    def _write_alert_file(self, alert: dict):
        """
        Append the alert as one JSON line to <alerts_dir>/alerts.jsonl.

        This is the evidence trail for your report: even with email and
        Telegram switched off you can prove the detection worked.
        """
        if not self.alerts_dir:
            self.last_result["file"] = "off"
            return
        try:
            os.makedirs(self.alerts_dir, exist_ok=True)
            path = os.path.join(self.alerts_dir, "alerts.jsonl")
            record = dict(alert)
            record["recorded_at"] = datetime.now().isoformat(timespec="seconds")
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
            self.last_result["file"] = path
        except Exception as e:
            self.last_result["file"] = f"error: {e}"
            print(f"  [ERROR] Could not write the alert file: {e}")
