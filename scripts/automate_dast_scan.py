#!/usr/bin/env python3
"""
DAST scan automation for OpenShift operators (OOBTKUBE).

Generic, config-driven framework. All operator-specific settings (namespace, CRs)
and tooling paths are defined in a YAML config file. Use --config to specify
which operator config to use.

Prerequisites:
  - OpenShift cluster with oc CLI configured
  - Operator installed in the configured namespace
  - Python 3.x with PyYAML

Usage:
  python3 scripts/automate_dast_scan.py --config config/oobtkube/ztwim.yaml
  python3 scripts/automate_dast_scan.py --config config/oobtkube/ztwim.yaml --callback-ip 10.0.0.1
"""

import sys
from pathlib import Path

# Ensure repo root is in path for dast and exports imports
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import argparse
import os
import subprocess

from dast.config import load_config, get_gcs_config, get_app_name
from dast.utils import get_script_dir, get_timestamp_dir, require_pyyaml
from dast.oc import check_oc_prerequisites, get_api_url_and_token
from dast.oobtkube import (
    get_framework,
    get_cr_configs,
    ensure_rapidast,
    migrate_flat_config_to_operator_dir,
    restore_crs,
    export_crs,
    get_callback_ip,
    run_oobtkube_scans,
    print_summary,
)

DEFAULT_CONFIG = "config/oobtkube/ztwim.yaml"


def main():
    require_pyyaml()

    parser = argparse.ArgumentParser(
        description="DAST scan automation for OpenShift operators (OOBTKUBE, config-driven)"
    )
    parser.add_argument(
        "--config",
        "-c",
        default=DEFAULT_CONFIG,
        help=f"Path to operator config YAML (default: {DEFAULT_CONFIG})",
    )
    parser.add_argument(
        "--namespace",
        default=None,
        help="Operator namespace (overrides config file)",
    )
    parser.add_argument(
        "--callback-ip",
        default=None,
        help="Callback IP (reachable from cluster pods). Auto-detect if not set.",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=120,
        help="Scan duration in seconds (default: 120)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=12345,
        help="Callback port (default: 12345)",
    )
    parser.add_argument(
        "--download-rapidast",
        action="store_true",
        help="Clone RapiDAST from GitHub if not present",
    )
    parser.add_argument(
        "--skip-export",
        action="store_true",
        help="Skip CR export; use existing files in Cr-Configs/",
    )
    parser.add_argument(
        "--skip-upload",
        action="store_true",
        help="Skip GCS upload (used when run from run_all_dast_scans.py)",
    )

    args = parser.parse_args()

    script_dir = get_script_dir()
    os.chdir(script_dir)

    config_path = script_dir / args.config
    config = load_config(config_path)
    if not config:
        print(f"Error: Config file not found or empty: {config_path}")
        print(f"  Use --config to specify a valid config file.")
        sys.exit(1)

    framework = get_framework(config)
    cr_configs = get_cr_configs(config)
    namespace = args.namespace or config.get("namespace")

    if not namespace:
        print("Error: namespace is required. Set it in config file or use --namespace.")
        sys.exit(1)
    if not cr_configs and not args.skip_export:
        print("Error: cr_configs is required in config file (or use --skip-export with existing Cr-Configs/).")
        sys.exit(1)

    print("=" * 60)
    print("Step 0: Ensuring RapiDAST is available...")
    print("=" * 60)
    rapidast_path = ensure_rapidast(script_dir, framework, download=args.download_rapidast)
    print()

    callback_ip = args.callback_ip or get_callback_ip()
    if not callback_ip:
        print("Error: Could not determine callback IP. Use --callback-ip.")
        sys.exit(1)

    timestamp = get_timestamp_dir()
    operator_name = config.get("operator", "default")
    result_dir = script_dir / framework["resultBaseDir"] / operator_name / timestamp
    result_dir.mkdir(parents=True, exist_ok=True)
    config_dir = script_dir / framework["configDir"] / operator_name

    print(f"Config: {config_path}")
    print(f"Using callback IP: {callback_ip}")
    print(f"Result directory: {result_dir}")
    print(f"CR config directory: {config_dir}")
    print(f"Ensure firewall allows port {args.port}: sudo firewall-cmd --add-port={args.port}/tcp")
    print()

    check_oc_prerequisites(namespace)

    migrate_flat_config_to_operator_dir(config_dir, cr_configs)
    restore_crs(namespace, config_dir)

    if not args.skip_export:
        export_crs(namespace, config_dir, cr_configs)
    else:
        print(f"Skipping CR export (--skip-export). Using existing {config_dir}/")
        config_dir.mkdir(parents=True, exist_ok=True)

    run_oobtkube_scans(
        callback_ip, args.duration, args.port,
        config_dir, result_dir, rapidast_path, framework["oobtkubeScript"]
    )
    print_summary(result_dir)

    gcs_config = get_gcs_config(config)
    bucket_name = gcs_config.get("bucketName")
    if bucket_name and not args.skip_upload:
        try:
            from exports.gcs_export import GoogleCloudStorage

            app_name = get_app_name(config)
            if not app_name:
                print("  [WARN] application.shortName not set; skipping GCS export")
            else:
                keyfile = gcs_config.get("keyFile")
                if keyfile and not os.path.isabs(keyfile):
                    keyfile = str(script_dir / keyfile)
                gcs = GoogleCloudStorage(
                    bucket_name=bucket_name,
                    app_name=app_name,
                    directory=gcs_config.get("directory"),
                    keyfile=keyfile,
                )
                gcs.export_scan(str(result_dir))
        except ImportError as e:
            print(f"  [FAIL] GCS export requires google-cloud-storage: pip install -r requirements.txt")
            print(f"         {e}")
        except Exception as e:
            print(f"  [FAIL] GCS export failed: {e}")

    print("Done.")
    print(f"Results saved to: {result_dir}")


if __name__ == "__main__":
    main()
