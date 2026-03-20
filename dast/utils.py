"""Shared utilities for DAST scan automation."""

import subprocess
import sys
from datetime import datetime
from pathlib import Path


def get_script_dir():
    """Return repo root (parent of dast/)."""
    return Path(__file__).parent.parent.resolve()


def run_cmd(cmd, check=True, capture=True):
    """Run shell command and return output."""
    result = subprocess.run(
        cmd,
        shell=True,
        capture_output=capture,
        text=True,
    )
    if check and result.returncode != 0:
        print(f"Error running: {cmd}")
        print(result.stderr or result.stdout)
        sys.exit(1)
    return (result.stdout or "").strip() if capture else None


def get_timestamp_dir():
    """Return timestamped directory name: YYYY-MM-DD_HH-MM-SS"""
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def require_pyyaml():
    """Ensure PyYAML is available; exit if not."""
    try:
        import yaml  # noqa: F401
    except ImportError:
        print("Error: PyYAML required. Install with: pip install -r requirements.txt")
        sys.exit(1)
