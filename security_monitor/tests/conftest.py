"""
Makes "from modules..." work when pytest is run from anywhere.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # security_monitor/
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
