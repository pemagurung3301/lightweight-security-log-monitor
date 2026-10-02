"""
alerter.py
──────────
Sends security alerts via two channels:
  1. Email (using Gmail's SMTP server)
  2. Telegram (using a Telegram Bot)

KEY CONCEPTS:
  SMTP = Simple Mail Transfer Protocol (how email gets sent)
  API  = Application Programming Interface
         (Telegram gives us a URL we can call to send a message)
"""

import smtplib                          # built-in Python email library
import urllib.request                   # built-in Python HTTP library
import urllib.parse
import json
import ssl
from email.mime.text    import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime


class Alerter:
    """
    Sends alerts via Email and/or Telegram.
    Which channels are used depends on what's enabled in settings.yaml.
    """

    def __init__(self, config: dict):
        self.email_cfg    = config.get("email",    {})
        self.telegram_cfg = config.get("telegram", {})

    def send(self, alert: dict):
        """
        Send an alert through all enabled channels.
        This is the only method you need to call from outside.
        """
        message = alert.get("message", "Security alert triggered.")

        if self.email_cfg.get("enabled", False):
            self._send_email(alert, message)

        if self.telegram_cfg.get("enabled", False):
            self._send_telegram(message)

    # ── EMAIL ─────────────────────────────────────────────────
    def _send_email(self, alert: dict, message: str):
        """
        Send an alert email using Gmail SMTP.

        SETUP STEPS (do this once):
        1. Go to your Google Account → Security → 2-Step Verification (turn on)
        2. Search for "App passwords" in Google Account settings
        3. Create an App Password for "Mail"
        4. Paste that 16-character password into settings.yaml
        """
        cfg = self.email_cfg

        # Build the email
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[SECURITY ALERT] Brute-Force Detected – {alert.get('source_ip','?')}"
        msg["From"]    = cfg["sender_email"]
        msg["To"]      = cfg["recipient_email"]

        # Plain text body
        body = (
            f"Security Alert from your Log Monitor\n"
            f"{'='*40}\n\n"
            f"{message}\n\n"
            f"{'='*40}\n"
            f"Sent by: Lightweight SME Security Monitor\n"
            f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        )
        msg.attach(MIMEText(body, "plain"))

        # Send it
        try:
            context = ssl.create_default_context()
            with smtplib.SMTP(cfg["smtp_server"], cfg["smtp_port"]) as server:
                server.ehlo()
                server.starttls(context=context)       # encrypt the connection
                server.login(cfg["sender_email"], cfg["sender_password"])
                server.sendmail(cfg["sender_email"], cfg["recipient_email"], msg.as_string())

            print(f"  [✓] Email alert sent to {cfg['recipient_email']}")

        except smtplib.SMTPAuthenticationError:
            print("  [ERROR] Email login failed. Check your Gmail App Password in settings.yaml")
        except Exception as e:
            print(f"  [ERROR] Failed to send email: {e}")

    # ── TELEGRAM ──────────────────────────────────────────────
    def _send_telegram(self, message: str):
        """
        Send an alert to a Telegram chat using a Bot.

        SETUP STEPS (do this once):
        1. Open Telegram → search for "@BotFather"
        2. Send /newbot → follow instructions → copy the token
        3. Send a message to your new bot
        4. Visit: https://api.telegram.org/bot<TOKEN>/getUpdates
           and copy the "chat":{"id": ...} number
        5. Paste both into settings.yaml
        """
        cfg = self.telegram_cfg
        token   = cfg.get("bot_token", "")
        chat_id = cfg.get("chat_id",   "")

        if not token or not chat_id:
            print("  [ERROR] Telegram bot_token or chat_id is empty in settings.yaml")
            return

        # Telegram Bot API URL
        url = f"https://api.telegram.org/bot{token}/sendMessage"

        # Data to send
        data = urllib.parse.urlencode({
            "chat_id": chat_id,
            "text":    message,
            "parse_mode": "HTML"
        }).encode("utf-8")

        try:
            req      = urllib.request.Request(url, data=data, method="POST")
            response = urllib.request.urlopen(req, timeout=10)
            result   = json.loads(response.read().decode("utf-8"))

            if result.get("ok"):
                print(f"  [✓] Telegram alert sent to chat {chat_id}")
            else:
                print(f"  [ERROR] Telegram API error: {result}")

        except Exception as e:
            print(f"  [ERROR] Failed to send Telegram message: {e}")
