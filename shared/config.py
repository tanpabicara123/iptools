
import os

# Base directory
SCRIPT_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# File paths
LOG_FILE     = os.path.expanduser("~/.iptracker_log")
TIME_FILE    = os.path.expanduser("~/.iptracker_time")
TARGETS_FILE = os.path.expanduser("~/.iptracker_targets.txt")
EXPORTS_DIR  = os.path.join(SCRIPT_DIR, "exports")

def ensure_exports_dir():
    if not os.path.exists(EXPORTS_DIR):
        os.makedirs(EXPORTS_DIR)


