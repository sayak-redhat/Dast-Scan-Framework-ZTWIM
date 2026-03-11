#!/usr/bin/env python3
"""
DAST scan automation for OpenShift operators.

Generic, config-driven framework. All operator-specific settings (namespace, CRs)
and tooling paths are defined in a YAML config file. Use --config to specify
which operator config to use.

Prerequisites:
  - OpenShift cluster with oc CLI configured
  - Operator installed in the configured namespace
  - Python 3.x with PyYAML

Usage:
  python3 automate_dast_scan.py --config config/ztwim.yaml
  python3 automate_dast_scan.py --config config/ztwim.yaml --callback-ip 10.0.0.1
"""

import argparse
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

try:
    import yaml
except ImportError:
    print("Error: PyYAML required. Install with: pip install -r requirements.txt")
    sys.exit(1)

DEFAULT_CONFIG = "config/ztwim.yaml"


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


def get_framework(config):
    """Extract framework settings with defaults."""
    fw = config.get("framework") or {}
    return {
        "rapidastRepo": fw.get("rapidastRepo", "https://github.com/RedHatProductSecurity/rapidast.git"),
        "rapidastDir": fw.get("rapidastDir", "rapidast"),
        "configDir": fw.get("configDir", "Cr-Configs"),
        "resultBaseDir": fw.get("resultBaseDir", "Dastscan-op"),
        "oobtkubeScript": fw.get("oobtkubeScript", "scanners/generic/tools/oobtkube.py"),
    }


def get_cr_configs(config):
    """Extract cr_configs from config as list of (plural, name) tuples."""
    cr_list = config.get("cr_configs")
    if not cr_list:
        return []
    result = []
    for item in cr_list:
        if isinstance(item, dict):
            plural = item.get("plural") or item.get("resource")
            name = item.get("name") or item.get("instance")
            if plural and name:
                result.append((plural, name))
        elif isinstance(item, (list, tuple)) and len(item) >= 2:
            result.append((str(item[0]), str(item[1])))
    return result


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


def ensure_rapidast(script_dir, framework, download=False):
    """Ensure rapidast exists. Clone from GitHub only if not present. Never re-download."""
    rapidast_path = script_dir / framework["rapidastDir"]
    oobtkube_path = rapidast_path / framework["oobtkubeScript"]

    if oobtkube_path.exists():
        print(f"  [OK] RapiDAST found at {rapidast_path} (skipping download)")
        return rapidast_path

    if rapidast_path.exists():
        print(f"  [FAIL] RapiDAST directory exists but OOBTKUBE not found at {oobtkube_path}")
        print(f"  Remove the rapidast directory, then run with --download-rapidast")
        sys.exit(1)

    if not download:
        print(f"  [FAIL] RapiDAST not found at {rapidast_path}")
        print(f"  Run with --download-rapidast to clone from GitHub")
        sys.exit(1)

    repo = framework["rapidastRepo"]
    print(f"  Cloning RapiDAST from {repo}...")
    result = subprocess.run(
        f"git clone {repo} {rapidast_path}",
        shell=True,
        cwd=script_dir,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"  [FAIL] Could not clone RapiDAST: {result.stderr}")
        sys.exit(1)
    print(f"  [OK] RapiDAST cloned to {rapidast_path}")

    if not oobtkube_path.exists():
        print(f"  [FAIL] OOBTKUBE script not found at {oobtkube_path}")
        sys.exit(1)

    return rapidast_path


def restore_crs(namespace, config_dir):
    """Restore CRs to clean state from Cr-Configs (from previous run). Ensures clean baseline before scan."""
    config_dir = Path(config_dir)
    if not config_dir.exists():
        return

    yaml_files = list(config_dir.glob("*-cr-oobtkube.yaml"))
    if not yaml_files:
        return

    print("=" * 60)
    print("Precheck: Restoring CRs to clean state (from previous run)...")
    print("=" * 60)

    for f in sorted(yaml_files):
        try:
            result = subprocess.run(
                f"oc apply -f {f.resolve()} -n {namespace}",
                shell=True,
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                print(f"  [OK] Restored {f.name}")
            else:
                err = (result.stderr or result.stdout or "")[:100]
                print(f"  [WARN] {f.name}: {err}")
        except Exception as e:
            print(f"  [WARN] {f.name}: {e}")

    print()


def check_prerequisites(namespace):
    """Verify cluster access and operator/operand presence."""
    print("=" * 60)
    print("Step 1: Checking prerequisites...")
    print("=" * 60)

    try:
        run_cmd("oc version", check=True)
        print("  [OK] oc CLI available")
    except Exception:
        print("  [FAIL] oc CLI not found or not configured")
        sys.exit(1)

    try:
        run_cmd("oc whoami", check=True)
        print("  [OK] Cluster access verified")
    except Exception:
        print("  [FAIL] Cannot access cluster. Check KUBECONFIG.")
        sys.exit(1)

    try:
        result = subprocess.run(
            f"oc get namespace {namespace} -o name",
            shell=True,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print(f"  [FAIL] Namespace {namespace} not found")
            sys.exit(1)
        print(f"  [OK] Namespace {namespace} exists")
    except Exception:
        print(f"  [FAIL] Namespace {namespace} not found")
        sys.exit(1)

    try:
        out = run_cmd(f"oc get pods -n {namespace} --no-headers 2>/dev/null")
        pods = [line for line in out.split("\n") if line and "Running" in line]
        if len(pods) < 3:
            print(f"  [WARN] Few pods running ({len(pods)}). Operator may not be fully ready.")
        else:
            print(f"  [OK] {len(pods)} pods running in namespace")
    except Exception:
        print("  [WARN] Could not verify pods")

    print()


def export_crs(namespace, config_dir, cr_configs):
    """Export all CRs from cluster."""
    print("=" * 60)
    print("Step 2: Exporting CRs from cluster...")
    print("=" * 60)

    config_dir = Path(config_dir)
    config_dir.mkdir(parents=True, exist_ok=True)

    for plural, cr_name in cr_configs:
        try:
            result = subprocess.run(
                f"oc get {plural} {cr_name} -n {namespace} -o yaml",
                shell=True,
                capture_output=True,
                text=True,
            )
            out = result.stdout or ""
            if result.returncode != 0 or not out or "Error" in out:
                print(f"  [SKIP] {plural}/{cr_name} not found")
                continue

            data = yaml.safe_load(out)
            meta = data.get("metadata", {})
            metadata = {"name": meta.get("name", cr_name)}
            ns = meta.get("namespace") or namespace
            if ns:
                metadata["namespace"] = ns
            minimal = {
                "apiVersion": data.get("apiVersion"),
                "kind": data.get("kind"),
                "metadata": metadata,
                "spec": data.get("spec", {}),
            }
            if minimal["spec"] is None:
                minimal["spec"] = {}

            filepath = config_dir / f"{plural}-cr-oobtkube.yaml"
            with open(filepath, "w") as f:
                yaml.dump(minimal, f, default_flow_style=False, sort_keys=False)

            print(f"  [OK] Exported {plural} -> {filepath}")
        except Exception as e:
            print(f"  [FAIL] {plural}: {e}")

    print()


def get_callback_ip():
    """Get callback IP from host."""
    for cmd in [
        "hostname -I 2>/dev/null | awk '{print $1}'",
        "ip route get 1 2>/dev/null | awk '{print $7; exit}'",
    ]:
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            ip = (result.stdout or "").strip()
            if ip:
                ip = ip.split()[0] if " " in ip else ip.strip()
                parts = ip.split(".")
                if len(parts) == 4 and all(p.isdigit() for p in parts):
                    return ip
        except Exception:
            continue
    return None


def run_oobtkube_scans(callback_ip, duration, port, config_dir, result_dir, rapidast_path, oobtkube_script):
    """Run OOBTKUBE for each CR config."""
    print("=" * 60)
    print("Step 3: Running OOBTKUBE scans...")
    print("=" * 60)

    oobtkube_path = rapidast_path / oobtkube_script
    config_files = list(config_dir.glob("*.yaml"))

    if not config_files:
        print(f"  [FAIL] No YAML files found in {config_dir}")
        sys.exit(1)

    for config_file in sorted(config_files):
        base = config_file.stem
        output_file = result_dir / f"oobtkube-{base}-results.sarif"

        print(f"  Scanning: {config_file.name} -> {output_file.name}")

        cmd = [
            sys.executable,
            str(oobtkube_path),
            "-d", str(duration),
            "-p", str(port),
            "-i", callback_ip,
            "-f", str(config_file),
            "-o", str(output_file),
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=duration + 30,
                cwd=str(rapidast_path),
            )
            if result.returncode != 0:
                err = (result.stderr or "")[:200]
                print(f"    [WARN] Exit code {result.returncode}: {err}")
            else:
                print(f"    [OK] Completed")
        except subprocess.TimeoutExpired:
            print(f"    [WARN] Timeout")
        except Exception as e:
            print(f"    [FAIL] {e}")

    print()


def print_summary(result_dir):
    """Print summary of results."""
    print("=" * 60)
    print("Step 4: Summary")
    print("=" * 60)

    result_files = list(result_dir.glob("*.sarif"))
    if not result_files:
        print("  No result files found.")
        return

    print(f"  Results stored in: {result_dir}")
    for f in sorted(result_files):
        size = f.stat().st_size
        print(f"    - {f.name} ({size} bytes)")

    print()
    print(f"  To view: cat {result_dir}/oobtkube-*-results.sarif | jq .")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="DAST scan automation for OpenShift operators (config-driven)"
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

    args = parser.parse_args()

    script_dir = Path(__file__).parent.resolve()
    os.chdir(script_dir)

    # Load config
    config_path = script_dir / args.config
    config = load_config(config_path)
    if not config:
        print(f"Error: Config file not found or empty: {config_path}")
        print(f"  Use --config to specify a valid config file.")
        sys.exit(1)

    framework = get_framework(config)
    cr_configs = get_cr_configs(config)
    namespace = args.namespace or config.get("namespace")

    # Validate required config
    if not namespace:
        print("Error: namespace is required. Set it in config file or use --namespace.")
        sys.exit(1)
    if not cr_configs and not args.skip_export:
        print("Error: cr_configs is required in config file (or use --skip-export with existing Cr-Configs/).")
        sys.exit(1)

    # Ensure RapiDAST exists
    print("=" * 60)
    print("Step 0: Ensuring RapiDAST is available...")
    print("=" * 60)
    rapidast_path = ensure_rapidast(script_dir, framework, download=args.download_rapidast)
    print()

    callback_ip = args.callback_ip or get_callback_ip()
    if not callback_ip:
        print("Error: Could not determine callback IP. Use --callback-ip.")
        sys.exit(1)

    # Create timestamped result directory
    timestamp = get_timestamp_dir()
    operator_name = config.get("operator", "default")
    result_dir = script_dir / framework["resultBaseDir"] / operator_name / timestamp
    result_dir.mkdir(parents=True, exist_ok=True)
    config_dir = script_dir / framework["configDir"]

    print(f"Config: {config_path}")
    print(f"Using callback IP: {callback_ip}")
    print(f"Result directory: {result_dir}")
    print(f"Ensure firewall allows port {args.port}: sudo firewall-cmd --add-port={args.port}/tcp")
    print()

    check_prerequisites(namespace)

    restore_crs(namespace, config_dir)

    if not args.skip_export:
        export_crs(namespace, config_dir, cr_configs)
    else:
        print("Skipping CR export (--skip-export). Using existing Cr-Configs/")
        config_dir.mkdir(parents=True, exist_ok=True)

    run_oobtkube_scans(
        callback_ip, args.duration, args.port,
        config_dir, result_dir, rapidast_path, framework["oobtkubeScript"]
    )
    print_summary(result_dir)

    # Export to GCS if configured
    gcs_config = config.get("config", {}).get("googleCloudStorage", {})
    bucket_name = gcs_config.get("bucketName")
    if bucket_name:
        try:
            from exports.gcs_export import GoogleCloudStorage

            app_name = (
                config.get("application", {}).get("shortName")
                or config.get("application", {}).get("ProductName")
            )
            if not app_name:
                print("  [WARN] application.shortName not set; skipping GCS export")
            else:
                gcs = GoogleCloudStorage(
                    bucket_name=bucket_name,
                    app_name=app_name,
                    directory=gcs_config.get("directory"),
                    keyfile=gcs_config.get("keyFile"),
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
