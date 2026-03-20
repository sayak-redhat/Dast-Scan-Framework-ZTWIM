#!/usr/bin/env python3
"""
Run both OOBTKUBE and ZAP scans, then upload a single combined tarball to GCS.

The tarball contains:
  - oobtkube-op/ztwim/<timestamp>/
  - zap-op/ZTWIM-Operator-ZAP/DAST-*-RapiDAST-*/
  - zap-op/ZTWIM-Operands-ZAP/DAST-*-RapiDAST-*/

Uploaded to: gs://{bucket}/operators/ztwim/{timestamp}-RapiDAST-ZTWIM-DAST-{random}.tgz

Usage:
  python3 run_all_dast_scans.py --operator ztwim
  python3 run_all_dast_scans.py --operator eso
  python3 run_all_dast_scans.py --config config/oobtkube/ztwim.yaml --zap-config config/zap/ztwim.yaml
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

from dast.config import load_config, get_operator, get_gcs_config, get_app_name
from dast.utils import get_script_dir, require_pyyaml
from dast.oobtkube import get_callback_ip
from dast.zap import get_zap_scan_dirs

OOBTKUBE_CONFIG_DIR = "config/oobtkube"
ZAP_CONFIG_DIR = "config/zap"
OOBTKUBE_BASE = "oobtkube-op"
ZAP_BASE = "zap-op"
DAST_PREFIX = "DAST-"
RAPIDAST_PREFIX = "RapiDAST-"


def get_latest_subdir(parent_dir, prefix="", suffix=""):
    """Get latest subdir in parent_dir (by name). Optionally filter by prefix/suffix."""
    parent = Path(parent_dir)
    if not parent.exists():
        return None
    subdirs = [d for d in parent.iterdir() if d.is_dir()]
    if prefix:
        subdirs = [d for d in subdirs if d.name.startswith(prefix)]
    if suffix:
        subdirs = [d for d in subdirs if suffix in d.name]
    if not subdirs:
        return None
    subdirs.sort(key=lambda d: d.name, reverse=True)
    return subdirs[0]


def main():
    require_pyyaml()

    parser = argparse.ArgumentParser(
        description="Run OOBTKUBE + ZAP scans and upload combined results to GCS"
    )
    parser.add_argument(
        "--operator",
        "-o",
        default=None,
        help="Operator name (e.g. ztwim, eso). Uses config/oobtkube/<operator>.yaml and config/zap/<operator>.yaml. Required unless --config is set.",
    )
    parser.add_argument(
        "--config",
        "-c",
        default=None,
        help="Path to OOBTKUBE config YAML. Alternative to --operator.",
    )
    parser.add_argument(
        "--zap-config",
        default=None,
        help="Path to ZAP config YAML. If not set, uses config/zap/<operator>.yaml. ZAP is skipped if config does not exist.",
    )
    parser.add_argument(
        "--callback-ip",
        default=None,
        help="Callback IP for OOBTKUBE. Auto-detect if not set.",
    )
    parser.add_argument(
        "--skip-upload",
        action="store_true",
        help="Skip GCS upload",
    )
    parser.add_argument(
        "--download-rapidast",
        action="store_true",
        help="Pass to automate_dast_scan.py",
    )
    args = parser.parse_args()

    script_dir = get_script_dir()
    os.chdir(script_dir)

    # Resolve OOBTKUBE config path: --config or --operator required
    if args.config:
        config_path = script_dir / args.config if not Path(args.config).is_absolute() else Path(args.config)
    elif args.operator:
        config_path = script_dir / OOBTKUBE_CONFIG_DIR / f"{args.operator}.yaml"
    else:
        print("Error: Specify --operator <name> (e.g. ztwim, eso) or --config <path>")
        sys.exit(1)

    config = load_config(config_path)
    if not config:
        print(f"Error: Config file not found or empty: {config_path}")
        sys.exit(1)

    operator_name = get_operator(config)
    callback_ip = args.callback_ip or get_callback_ip()
    if not callback_ip:
        print("Error: Could not determine callback IP. Use --callback-ip.")
        sys.exit(1)

    # Resolve ZAP config path; ZAP is skipped if config does not exist
    if args.zap_config:
        zap_config_path = script_dir / args.zap_config if not Path(args.zap_config).is_absolute() else Path(args.zap_config)
    else:
        zap_config_path = script_dir / ZAP_CONFIG_DIR / f"{operator_name}.yaml"
    run_zap = zap_config_path.exists()

    print(f"Operator: {operator_name}")
    print(f"OOBTKUBE config: {config_path.relative_to(script_dir)}")
    print(f"ZAP config: {zap_config_path.relative_to(script_dir)} ({'found' if run_zap else 'not found, ZAP skipped'})")
    print()

    print("=" * 60)
    print("Step 1: Running OOBTKUBE scan...")
    print("=" * 60)
    oobtkube_cmd = [
        sys.executable,
        str(script_dir / "scripts" / "automate_dast_scan.py"),
        "--config", str(config_path),
        "--callback-ip", callback_ip,
        "--skip-upload",
    ]
    if args.download_rapidast:
        oobtkube_cmd.append("--download-rapidast")
    result = subprocess.run(oobtkube_cmd, cwd=str(script_dir))
    if result.returncode != 0:
        print(f"  [WARN] OOBTKUBE scan exited with {result.returncode}")

    print()
    if run_zap:
        print()
        print("=" * 60)
        print("Step 2: Running ZAP scan...")
        print("=" * 60)
        zap_cmd = [
            sys.executable,
            str(script_dir / "scripts" / "automate_zap_scan.py"),
            "--config", str(zap_config_path),
            "--skip-upload",
        ]
        result = subprocess.run(zap_cmd, cwd=str(script_dir))
        if result.returncode != 0:
            print(f"  [WARN] ZAP scan exited with {result.returncode}")
    else:
        print()
        print("=" * 60)
        print("Step 2: Skipping ZAP scan (no config at config/zap/{}.yaml)".format(operator_name))
        print("=" * 60)

    print()
    print("=" * 60)
    print("Step 3: Collecting results and uploading to GCS...")
    print("=" * 60)

    result_dirs = []

    oobtkube_parent = script_dir / OOBTKUBE_BASE / operator_name
    oobtkube_latest = get_latest_subdir(oobtkube_parent)
    if oobtkube_latest and any(oobtkube_latest.glob("*.sarif")):
        result_dirs.append(oobtkube_latest)
        print(f"  [OK] OOBTKUBE: {oobtkube_latest.relative_to(script_dir)}")
    elif oobtkube_latest:
        print(f"  [WARN] OOBTKUBE dir empty (scan may have failed): {oobtkube_latest.relative_to(script_dir)}")
    else:
        print(f"  [WARN] No OOBTKUBE results in {oobtkube_parent}")

    zap_scan_dirs = get_zap_scan_dirs(zap_config_path, script_dir) if run_zap else []
    if not zap_scan_dirs:
        zap_scan_dirs = ["ZTWIM-Operator-ZAP", "ZTWIM-Operands-ZAP"] if run_zap else []
    for scan_dir in zap_scan_dirs:
        parent = script_dir / ZAP_BASE / scan_dir
        latest = get_latest_subdir(parent, prefix=DAST_PREFIX, suffix=RAPIDAST_PREFIX)
        if latest:
            result_dirs.append(latest)
            print(f"  [OK] ZAP {scan_dir}: {latest.relative_to(script_dir)}")
        else:
            print(f"  [WARN] No ZAP results in {parent}")

    if not result_dirs:
        print("  [FAIL] No result directories found. Nothing to upload.")
        sys.exit(1)

    gcs_config = get_gcs_config(config)
    bucket_name = gcs_config.get("bucketName")
    if not bucket_name or args.skip_upload:
        print("  Skipping GCS upload (--skip-upload or no bucket configured)")
        sys.exit(0)

    try:
        from exports.gcs_export import GoogleCloudStorage
    except ImportError as e:
        print(f"  [FAIL] GCS export requires google-cloud-storage: pip install -r requirements.txt")
        print(f"         {e}")
        sys.exit(1)

    app_name = get_app_name(config, "ZTWIM-DAST")
    keyfile = gcs_config.get("keyFile")
    if keyfile and not os.path.isabs(keyfile):
        keyfile = str(script_dir / keyfile)

    gcs = GoogleCloudStorage(
        bucket_name=bucket_name,
        app_name=app_name,
        directory=gcs_config.get("directory"),
        keyfile=keyfile,
    )
    gcs.export_combined_scan(result_dirs, script_dir)

    print()
    print("Done.")


if __name__ == "__main__":
    main()
