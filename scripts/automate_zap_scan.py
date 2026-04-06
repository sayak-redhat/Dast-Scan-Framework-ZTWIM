#!/usr/bin/env python3
"""
ZAP scan automation for OpenShift operators.

Config-driven automation: renders runtime ZAP configs (API URL + token injected
into a temp dir), runs operator and operands scans via Podman/RapiDAST, then
auto-cleans the temp configs.  On-disk template YAMLs are never modified.

Flat SARIF/HTML under results/zap/flat/<operator>/<timestamp>/;
RapiDAST trees under results/zap/rapidast/<shortName>/.

Prerequisites:
  - OpenShift cluster with oc CLI configured
  - Podman (or Docker) installed
  - Python 3.x with PyYAML

Usage:
  python3 scripts/automate_zap_scan.py --config config/operators/ztwim/zap/zap.yaml
  python3 scripts/automate_zap_scan.py --config config/operators/ztwim/zap/zap.yaml --skip-upload
  python3 scripts/automate_zap_scan.py --config config/operators/ztwim/zap/zap.yaml --skip-config-update
  python3 scripts/automate_zap_scan.py --config ... --skip-bootstrap   # skip oc apply of dast-zap-setup.yaml
"""

import sys
from pathlib import Path

# Ensure repo root is in path for dast and exports imports
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import argparse
import os
import shutil
import subprocess
import tempfile

from dast.config import load_config, get_operator, get_gcs_config, ZAP_RAPIDAST_BASE, ZAP_FLAT_BASE
from dast.utils import get_script_dir, get_timestamp_dir, require_pyyaml
from dast.oc import (
    apply_zap_token_env_defaults,
    check_zap_prerequisites,
    ensure_zap_cluster_bootstrap,
    get_api_url_and_token,
    get_container_runtime,
    resolve_zap_sa_and_ns,
)
from dast.zap import (
    get_zap_configs,
    get_output_names,
    prepare_runtime_configs,
    run_zap_scans,
    print_summary,
    RAPIDAST_IMAGE,
)

DEFAULT_CONFIG = "config/operators/ztwim/zap/zap.yaml"


def main():
    require_pyyaml()

    parser = argparse.ArgumentParser(
        description="ZAP scan automation for OpenShift operators (config-driven)"
    )
    parser.add_argument(
        "--config",
        "-c",
        default=DEFAULT_CONFIG,
        help=f"Path to ZAP config YAML (default: {DEFAULT_CONFIG})",
    )
    parser.add_argument(
        "--skip-upload",
        action="store_true",
        help="Skip GCS upload even if configured",
    )
    parser.add_argument(
        "--skip-config-update",
        action="store_true",
        help="Use existing config values; do not update API URL/token",
    )
    parser.add_argument(
        "--skip-bootstrap",
        action="store_true",
        help="Do not run oc apply on dast-zap-setup.yaml (namespace/SA/RBAC next to zap.yaml)",
    )
    args = parser.parse_args()

    script_dir = get_script_dir()
    os.chdir(script_dir)

    config_path = script_dir / args.config
    config = load_config(config_path)
    if not config:
        print(f"Error: Config file not found or empty: {config_path}")
        sys.exit(1)

    operator_name = get_operator(config)
    zap_configs = get_zap_configs(config, script_dir, operator_name)
    if not zap_configs:
        print("Error: No ZAP config files found.")
        print(f"  Add zap.configs to {config_path} or ensure config/operators/{operator_name}/zap/zap-operator.yaml exists.")
        sys.exit(1)

    zap_section = config.get("zap") or {}
    apply_zap_token_env_defaults(zap_section)
    sa, ns = resolve_zap_sa_and_ns(zap_section)
    if sa != "default" or ns != "default":
        print(f"ZAP token: service account {sa!r} in namespace {ns!r} (from env or zap.* in config)")
        print()
    rapidast_image = zap_section.get("rapidastImage", RAPIDAST_IMAGE)
    timeout_minutes = zap_section.get("timeoutMinutes", 90)
    output_names = get_output_names(config, len(zap_configs))

    timestamp = get_timestamp_dir()
    rapidast_mount = script_dir / ZAP_RAPIDAST_BASE
    result_dir = script_dir / ZAP_FLAT_BASE / operator_name / timestamp

    print(f"Config: {config_path}")
    print(f"ZAP configs: {[str(c.relative_to(script_dir)) for c in zap_configs]}")
    print(f"Results: {result_dir}")
    print()

    check_zap_prerequisites()

    ensure_zap_cluster_bootstrap(
        config_path,
        zap_section=zap_section,
        skip=args.skip_bootstrap,
    )

    runtime = get_container_runtime()

    if not args.skip_config_update:
        api_server, token = get_api_url_and_token(zap_section)
        tmpdir = tempfile.mkdtemp(prefix="zap-runtime-")
        try:
            scan_configs = prepare_runtime_configs(
                zap_configs, api_server, token, tmpdir
            )
            run_zap_scans(
                scan_configs,
                rapidast_mount,
                result_dir,
                output_names,
                runtime,
                rapidast_image,
                timeout_minutes=timeout_minutes,
                script_dir=script_dir,
            )
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
    else:
        print("Skipping config update (--skip-config-update); mounting templates as-is.")
        print()
        run_zap_scans(
            zap_configs,
            rapidast_mount,
            result_dir,
            output_names,
            runtime,
            rapidast_image,
            timeout_minutes=timeout_minutes,
            script_dir=script_dir,
        )

    print_summary(result_dir)

    gcs_config = get_gcs_config(config)
    bucket_name = gcs_config.get("bucketName")
    if bucket_name and not args.skip_upload:
        try:
            upload_script = script_dir / "exports" / "upload_zap_results.py"
            if upload_script.exists():
                result = subprocess.run(
                    [sys.executable, str(upload_script), "--config", str(config_path), "--latest"],
                    cwd=str(script_dir),
                    capture_output=True,
                    text=True,
                )
                if result.returncode == 0:
                    print(result.stdout or "")
                else:
                    print(f"  [WARN] GCS upload failed: {result.stderr or result.stdout}")
            else:
                print("  [WARN] exports/upload_zap_results.py not found; skipping GCS upload")
        except Exception as e:
            print(f"  [WARN] GCS upload failed: {e}")
    elif args.skip_upload:
        print("Skipping individual GCS upload (--skip-upload; run_all_dast_scans.py uploads combined results).")

    print("Done.")
    print(f"Results saved to: {result_dir}")


if __name__ == "__main__":
    main()
