#!/usr/bin/env python3
"""
Trivy k8s misconfiguration scan via RapiDAST (generic_trivy).

Mounts kubeconfig at /opt/rapidast/.kube/config (see upstream template).
Flat SARIF: results/trivy/flat/<operator>/<timestamp>/
RapiDAST tree: results/trivy/rapidast/<application.shortName>/

Usage:
  python3 scripts/automate_trivy_scan.py --config config/operators/ztwim/trivy/trivy.yaml
  KUBECONFIG=/path/to/kubeconfig python3 scripts/automate_trivy_scan.py --kubeconfig ~/.kube/config
"""

import argparse
import os
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from dast.config import (
    load_config,
    get_operator,
    get_gcs_config,
    get_app_name,
    TRIVY_RAPIDAST_BASE,
    TRIVY_FLAT_BASE,
)
from dast.utils import get_script_dir, get_timestamp_dir, require_pyyaml
from dast.oc import check_zap_prerequisites, get_container_runtime
from dast.trivy import get_trivy_k8s_config_path, run_trivy_scan, print_trivy_summary
from dast.zap import RAPIDAST_IMAGE

DEFAULT_CONFIG = "config/operators/ztwim/trivy/trivy.yaml"


def main():
    require_pyyaml()

    parser = argparse.ArgumentParser(
        description="Trivy k8s scan via RapiDAST (generic_trivy)"
    )
    parser.add_argument(
        "--config",
        "-c",
        default=DEFAULT_CONFIG,
        help=f"Path to trivy orchestration YAML (default: {DEFAULT_CONFIG})",
    )
    parser.add_argument(
        "--kubeconfig",
        default=None,
        help="Kubeconfig file path (default: $KUBECONFIG or ~/.kube/config)",
    )
    parser.add_argument(
        "--skip-upload",
        action="store_true",
        help="Skip GCS upload even if configured",
    )
    args = parser.parse_args()

    script_dir = get_script_dir()
    os.chdir(script_dir)

    config_path = script_dir / args.config
    if not config_path.exists():
        print(f"Error: Config not found: {config_path}")
        sys.exit(1)

    config = load_config(config_path)
    if not config:
        print(f"Error: Empty config: {config_path}")
        sys.exit(1)

    operator_name = get_operator(config)
    trivy_section = config.get("trivy") or {}
    k8s_path = get_trivy_k8s_config_path(config_path, script_dir)
    if not k8s_path or not k8s_path.exists():
        print("Error: trivy.config not set or file missing in orchestration YAML.")
        sys.exit(1)

    rapidast_image = trivy_section.get("rapidastImage", RAPIDAST_IMAGE)
    timeout_minutes = trivy_section.get("timeoutMinutes", 45)

    timestamp = get_timestamp_dir()
    rapidast_mount = script_dir / TRIVY_RAPIDAST_BASE
    result_dir = script_dir / TRIVY_FLAT_BASE / operator_name / timestamp

    print(f"Config: {config_path.relative_to(script_dir)}")
    print(f"Trivy k8s config: {k8s_path.relative_to(script_dir)}")
    print(f"Results: {result_dir.relative_to(script_dir)}")
    print()

    check_zap_prerequisites()
    runtime = get_container_runtime()

    kube = args.kubeconfig or os.environ.get("KUBECONFIG")
    if kube:
        kube = str(Path(kube).expanduser())

    run_trivy_scan(
        k8s_path,
        rapidast_mount,
        result_dir,
        runtime,
        rapidast_image,
        timeout_minutes=timeout_minutes,
        script_dir=script_dir,
        kubeconfig_path=kube,
    )
    print_trivy_summary(result_dir)

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
    elif args.skip_upload:
        print("Skipping GCS upload (--skip-upload).")

    print("Done.")
    print(f"Results saved to: {result_dir}")


if __name__ == "__main__":
    main()
