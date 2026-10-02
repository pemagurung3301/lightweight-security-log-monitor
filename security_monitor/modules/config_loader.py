"""
config_loader.py
────────────────
Reads the settings.yaml file and returns it as a Python dictionary.
Think of it like loading your preferences before the app starts.

It also fills in sane defaults for anything you left out, and warns you
about settings that are still placeholders.
"""

import os
import sys

import yaml   # pip install pyyaml

# Sensible values used when settings.yaml does not mention a key.
DEFAULTS = {
    "check_interval_seconds": 10,
    "linux":   {"log_file": "/var/log/auth.log"},
    "windows": {"log_name": "Security"},
    "thresholds": {
        "failed_login_count": 5,
        "failed_login_window_seconds": 180,
        "alert_cooldown_seconds": 300,
    },
    "email":    {"enabled": False, "smtp_server": "smtp.gmail.com", "smtp_port": 587},
    "telegram": {"enabled": False},
    "alerts_dir": "logs",
}

_PLACEHOLDERS = {"YOUR_APP_PASSWORD", "YOUR_BOT_TOKEN", "YOUR_CHAT_ID",
                 "YOUR_EMAIL@gmail.com", "CHANGE_ME"}


def default_config_path() -> str:
    """Absolute path of config/settings.yaml next to this project."""
    here = os.path.dirname(os.path.abspath(__file__))          # .../modules
    return os.path.join(os.path.dirname(here), "config", "settings.yaml")


def load_config(path: str | None = None) -> dict:
    """
    Load the YAML config file.
    Exits with a helpful message if the file is missing.
    """
    path = path or default_config_path()

    if not os.path.exists(path):
        print(f"[ERROR] Config file not found: {path}")
        print("  Copy config/settings.example.yaml to config/settings.yaml and edit it.")
        sys.exit(1)

    try:
        with open(path, "r", encoding="utf-8") as f:
            loaded = yaml.safe_load(f)
    except yaml.YAMLError as e:
        print(f"[ERROR] {path} is not valid YAML:\n  {e}")
        sys.exit(1)

    if not isinstance(loaded, dict):
        print(f"[ERROR] {path} did not contain any settings.")
        sys.exit(1)

    config = _merge(DEFAULTS, loaded)
    config["_path"] = path
    config["_dir"] = os.path.dirname(os.path.abspath(path))

    print(f"[*] Config loaded from: {path}")
    _warn_about_placeholders(config)
    return config


# ── internals ────────────────────────────────────────────────
def _merge(defaults: dict, overrides: dict) -> dict:
    """Deep-merge user settings over the defaults (user wins)."""
    out = dict(defaults)
    for key, value in (overrides or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


def _warn_about_placeholders(config: dict):
    """Tell the user about settings they have not filled in yet."""
    email = config.get("email", {})
    if email.get("enabled"):
        if str(email.get("sender_password", "")) in _PLACEHOLDERS:
            print("[WARNING] email.enabled is true but sender_password is still a "
                  "placeholder – email alerts will be skipped.")
    telegram = config.get("telegram", {})
    if telegram.get("enabled"):
        if str(telegram.get("bot_token", "")) in _PLACEHOLDERS or \
           str(telegram.get("chat_id", "")) in _PLACEHOLDERS:
            print("[WARNING] telegram.enabled is true but bot_token/chat_id are still "
                  "placeholders – Telegram alerts will be skipped.")
