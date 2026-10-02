"""
config_loader.py
────────────────
Reads the settings.yaml file and returns it as a Python dictionary.
Think of it like loading your preferences before the app starts.
"""

import yaml   # pip install pyyaml
import sys
import os


def load_config(path: str) -> dict:
    """
    Load YAML config file from the given path.
    Exits with a helpful message if the file is missing.
    """
    if not os.path.exists(path):
        print(f"[ERROR] Config file not found: {path}")
        print("  Make sure 'config/settings.yaml' exists in your project folder.")
        sys.exit(1)

    with open(path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    print(f"[*] Config loaded from: {path}")
    return config
