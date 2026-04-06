#!/usr/bin/env python3
"""
Run OOBTKUBE, ZAP, and optionally Trivy k8s, then upload a single combined tarball to GCS.

The tarball contains:
  - results/oobtkube/ztwim/<timestamp>/
  - results/zap/rapidast/ZTWIM-Operator-ZAP/DAST-*-RapiDAST-*/
  - results/zap/rapidast/ZTWIM-Operands-ZAP/DAST-*-RapiDAST-*/
  - results/trivy/rapidast/ZTWIM-Trivy-K8s/DAST-*-RapiDAST-*/ (if config/operators/<op>/trivy/trivy.yaml exists)

Uploaded to: gs://{bucket}/operators/ztwim/{timestamp}-RapiDAST-ZTWIM-DAST-{random}.tgz

Usage:
  python3 run_all_dast_scans.py --operator ztwim
  python3 run_all_dast_scans.py --operator eso
  python3 run_all_dast_scans.py --config config/operators/ztwim/oobtkube.yaml --zap-config config/operators/ztwim/zap/zap.yaml
  python3 run_all_dast_scans.py --operator ztwim --skip-zap-config-update   # manual Bearer in config/operators/<op>/zap/zap-*.yaml
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

from dast.config import (
    load_config,
    get_operator,
    get_gcs_config,
    get_app_name,
    operator_oobtkube_config,
    operator_zap_config,
    operator_trivy_config,
    TRIVY_RAPIDAST_BASE,
)
from dast.utils import get_script_dir, require_pyyaml
from dast.oobtkube import get_callback_ip
from dast.zap import get_zap_scan_dirs
from dast.trivy import get_trivy_k8s_config_path, get_trivy_short_name

OOBTKUBE_BASE = "results/oobtkube"
ZAP_RAPIDAST_BASE = "results/zap/rapidast"
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
        description="Run OOBTKUBE + ZAP (+ optional Trivy) and upload combined results to GCS"
    )
    parser.add_argument(
        "--operator",
        "-o",
        default=None,
        help="Operator name (e.g. ztwim, eso). Uses config/operators/<operator>/oobtkube.yaml and zap/zap.yaml. Required unless --config is set.",
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
        help="Path to ZAP config YAML. If not set, uses config/operators/<operator>/zap/zap.yaml. ZAP is skipped if config does not exist.",
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
        help="Pass to automate_oobtkube_scan.py",
    )
    parser.add_argument(
        "--oobtkube-log-level",
        choices=("debug", "info", "warning", "error"),
        default=None,
        help="RapiDAST oobtkube --log-level (overrides config; default in config is debug)",
    )
    parser.add_argument(
        "--skip-zap-config-update",
        action="store_true",
        help="Pass --skip-config-update to ZAP: keep manual Bearer/API URLs in config/operators/<op>/zap/zap-*.yaml (no oc token injection)",
    )
    parser.add_argument(
        "--skip-zap-bootstrap",
        action="store_true",
        help="Pass --skip-bootstrap to ZAP: do not oc apply dast-zap-setup.yaml",
    )
    parser.add_argument(
        "--skip-trivy",
        action="store_true",
        help="Skip Trivy k8s scan even if config/operators/<operator>/trivy/trivy.yaml exists",
    )
    args = parser.parse_args()

    script_dir = get_script_dir()
    os.chdir(script_dir)

    # Resolve OOBTKUBE config path: --config or --operator required
    if args.config:
        config_path = script_dir / args.config if not Path(args.config).is_absolute() else Path(args.config)
    elif args.operator:
        config_path = operator_oobtkube_config(script_dir, args.operator)
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
        zap_config_path = operator_zap_config(script_dir, operator_name)
    run_zap = zap_config_path.exists()

    trivy_config_path = operator_trivy_config(script_dir, operator_name)
    run_trivy = trivy_config_path.exists() and not args.skip_trivy

    print(f"Operator: {operator_name}")
    print(f"OOBTKUBE config: {config_path.relative_to(script_dir)}")
    print(f"ZAP config: {zap_config_path.relative_to(script_dir)} ({'found' if run_zap else 'not found, ZAP skipped'})")
    if not trivy_config_path.exists():
        _trivy_msg = "not found"
    elif args.skip_trivy:
        _trivy_msg = "skipped (--skip-trivy)"
    else:
        _trivy_msg = "run"
    print(f"Trivy config: {trivy_config_path.relative_to(script_dir)} ({_trivy_msg})")
    print()

    print("=" * 60)
    print("Step 1: Running OOBTKUBE scan...")
    print("=" * 60)
    oobtkube_cmd = [
        sys.executable,
        str(script_dir / "scripts" / "automate_oobtkube_scan.py"),
        "--config", str(config_path),
        "--callback-ip", callback_ip,
        "--skip-upload",
    ]
    if args.download_rapidast:
        oobtkube_cmd.append("--download-rapidast")
    if args.oobtkube_log_level:
        oobtkube_cmd.extend(["--log-level", args.oobtkube_log_level])
    result = subprocess.run(oobtkube_cmd, cwd=str(script_dir))
    if result.returncode != 0:
        print(f"  [WARN] OOBTKUBE scan exited with {result.returncode}")

    print()
    if run_zap:
        print()
        print("=" * 60)
        print("Step 2: Running ZAP scan...")
        print("=" * 60)
        if args.skip_zap_config_update:
            print("  (ZAP: --skip-config-update — using Bearer/API URLs from config/operators/.../zap/zap-*.yaml as-is)")
        zap_cmd = [
            sys.executable,
            str(script_dir / "scripts" / "automate_zap_scan.py"),
            "--config", str(zap_config_path),
            "--skip-upload",
        ]
        if args.skip_zap_config_update:
            zap_cmd.append("--skip-config-update")
        if args.skip_zap_bootstrap:
            zap_cmd.append("--skip-bootstrap")
        result = subprocess.run(zap_cmd, cwd=str(script_dir))
        if result.returncode != 0:
            print(f"  [WARN] ZAP scan exited with {result.returncode}")
            print(
                "  Tip: Step 3 only collects ZAP output if RapiDAST creates "
                "results/zap/rapidast/<shortName>/DAST-*-RapiDAST-*/ — "
                "scroll up to Step 2 for oc token, kubeconfig, or Podman errors."
            )
    else:
        print()
        print("=" * 60)
        print("Step 2: Skipping ZAP scan (no config at config/operators/{}/zap/zap.yaml)".format(operator_name))
        print("=" * 60)

    if run_trivy:
        print()
        print("=" * 60)
        print("Step 2b: Running Trivy k8s scan...")
        print("=" * 60)
        trivy_cmd = [
            sys.executable,
            str(script_dir / "scripts" / "automate_trivy_scan.py"),
            "--config",
            str(trivy_config_path),
            "--skip-upload",
        ]
        result = subprocess.run(trivy_cmd, cwd=str(script_dir))
        if result.returncode != 0:
            print(f"  [WARN] Trivy scan exited with {result.returncode}")
    elif trivy_config_path.exists() and args.skip_trivy:
        print()
        print("=" * 60)
        print("Step 2b: Skipping Trivy (--skip-trivy)")
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
        parent = script_dir / ZAP_RAPIDAST_BASE / scan_dir
        latest = get_latest_subdir(parent, prefix=DAST_PREFIX, suffix=RAPIDAST_PREFIX)
        if latest:
            result_dirs.append(latest)
            print(f"  [OK] ZAP {scan_dir}: {latest.relative_to(script_dir)}")
        else:
            print(f"  [WARN] No ZAP results in {parent}")
            print(
                "        (Expected a subdir named DAST-*-RapiDAST-* from RapiDAST; "
                "missing means Step 2 did not complete a ZAP run or wrote elsewhere.)"
            )

    if run_trivy:
        k8s_cfg = get_trivy_k8s_config_path(trivy_config_path, script_dir)
        if k8s_cfg and k8s_cfg.exists():
            trivy_short = get_trivy_short_name(k8s_cfg)
            if trivy_short:
                trivy_parent = script_dir / TRIVY_RAPIDAST_BASE / trivy_short
                trivy_latest = get_latest_subdir(trivy_parent, prefix=DAST_PREFIX, suffix=RAPIDAST_PREFIX)
                if trivy_latest:
                    result_dirs.append(trivy_latest)
                    print(f"  [OK] Trivy {trivy_short}: {trivy_latest.relative_to(script_dir)}")
                else:
                    print(f"  [WARN] No Trivy results in {trivy_parent}")

    if not result_dirs:
        print("  [WARN] No result directories found.")
        if args.skip_upload:
            sys.exit(0)
        print("  [FAIL] Nothing to upload.")
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
