#!/usr/bin/env python3
"""
Upload ZAP scan results (operator and operands) to a GCP bucket.

Results are stored in results/zap/flat/<operator>/<timestamp>/ with flat SARIF files.
This script finds the latest timestamp directory and uploads it as a gzipped tarball.

Usage:
  python3 exports/upload_zap_results.py --config config/operators/ztwim/zap/zap.yaml
  python3 exports/upload_zap_results.py --config config/operators/ztwim/zap/zap.yaml --all
"""

import argparse
import os
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("Error: PyYAML required. Install with: pip install -r requirements.txt")
    sys.exit(1)

DEFAULT_CONFIG = "config/operators/ztwim/zap/zap.yaml"
RESULTS_BASE = "results/zap/flat"


def load_config(config_path):
    """Load YAML config from path. Return dict or empty dict."""
    config_path = Path(config_path)
    if not config_path.exists():
        return {}
    try:
        with open(config_path) as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        print(f"  [WARN] Could not load {config_path}: {e}")
        return {}


def find_latest_zap_result_dir(script_dir, operator_name):
    """
    Find the latest results/zap/flat/<operator>/<timestamp>/ directory.
    Returns Path to the timestamp dir, or None if not found.
    """
    results_base = script_dir / RESULTS_BASE / operator_name
    if not results_base.exists():
        return None

    timestamp_dirs = [d for d in results_base.iterdir() if d.is_dir()]
    if not timestamp_dirs:
        return None

    timestamp_dirs.sort(key=lambda d: d.name, reverse=True)
    return timestamp_dirs[0]


def find_zap_result_dirs(script_dir, operator_name, latest_only=True):
    """
    Find ZAP result directories under results/zap/flat/<operator>/<timestamp>/.
    Returns list of (result_dir_path,) tuples for upload.
    """
    if latest_only:
        latest = find_latest_zap_result_dir(script_dir, operator_name)
        if latest and any(latest.glob("*.sarif")):
            return [(str(latest),)]
        return []

    results_base = script_dir / RESULTS_BASE / operator_name
    if not results_base.exists():
        return []

    found = []
    for ts_dir in sorted(results_base.iterdir(), key=lambda d: d.name, reverse=True):
        if ts_dir.is_dir() and any(ts_dir.glob("*.sarif")):
            found.append((str(ts_dir),))
    return found


def main():
    parser = argparse.ArgumentParser(
        description="Upload ZAP scan results to GCP bucket"
    )
    parser.add_argument(
        "--config",
        "-c",
        default=DEFAULT_CONFIG,
        help=f"Path to ZAP config YAML (default: {DEFAULT_CONFIG})",
    )
    parser.add_argument(
        "--latest",
        action="store_true",
        default=True,
        help="Upload only the most recent result (default)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Upload all timestamped results, not just latest",
    )
    args = parser.parse_args()

    # Repo root (parent of exports/)
    script_dir = Path(__file__).parent.parent.resolve()
    os.chdir(script_dir)

    config_path = script_dir / args.config
    config = load_config(config_path)
    if not config:
        print(f"Error: Config file not found or empty: {config_path}")
        sys.exit(1)

    operator_name = config.get("operator", "ztwim")
    result_dirs = find_zap_result_dirs(
        script_dir, operator_name, latest_only=not args.all
    )
    if not result_dirs:
        print("No ZAP result directories found.")
        print(f"  Expected: {RESULTS_BASE}/{operator_name}/<timestamp>/")
        print(f"  Run: python3 scripts/automate_zap_scan.py --config {args.config}")
        sys.exit(0)

    gcs_config = config.get("config", {}).get("googleCloudStorage", {})
    bucket_name = gcs_config.get("bucketName")
    if not bucket_name:
        print("Error: config.googleCloudStorage.bucketName is not set.")
        print(f"  Add bucketName to {config_path}")
        sys.exit(1)

    directory = gcs_config.get("directory")
    app_name = (
        config.get("application", {}).get("shortName")
        or config.get("application", {}).get("ProductName")
        or "ZTWIM-DAST"
    )
    keyfile = gcs_config.get("keyFile")
    if keyfile and not os.path.isabs(keyfile):
        keyfile = str(script_dir / keyfile)

    try:
        from .gcs_export import GoogleCloudStorage
    except ImportError:
        # When run directly: python3 exports/upload_zap_results.py
        from gcs_export import GoogleCloudStorage

    print(f"Uploading {len(result_dirs)} ZAP result(s) to gs://{bucket_name}/{directory or 'RapiDAST'}/")
    for (result_dir,) in result_dirs:
        try:
            gcs = GoogleCloudStorage(
                bucket_name=bucket_name,
                app_name=app_name,
                directory=directory,
                keyfile=keyfile,
            )
            gcs.export_scan(result_dir)
        except Exception as e:
            print(f"  [FAIL] {result_dir}: {e}")

    print("Done.")


if __name__ == "__main__":
    main()
