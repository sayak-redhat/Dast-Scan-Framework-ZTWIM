#!/usr/bin/env python3
"""
Automated DAST Scanning for Zero Trust Workload Identity Manager (ZTWIM) Operator

Prerequisites:
  - OpenShift cluster with oc CLI configured
  - ZTWIM operator and operands installed in zero-trust-workload-identity-manager namespace
  - Python 3.x with PyYAML

Usage:
  python3 automate_dast_scan.py [--callback-ip IP] [--download-rapidast] [--namespace NAMESPACE]

Example:
  python3 automate_dast_scan.py --callback-ip 10.215.98.167
  python3 automate_dast_scan.py --download-rapidast
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

# CRDs to scan: (plural_name, cr_name)
CR_CONFIGS = [
    ("zerotrustworkloadidentitymanagers", "cluster"),
    ("spireservers", "cluster"),
    ("spireagents", "cluster"),
    ("spiffecsidrivers", "cluster"),
    ("spireoidcdiscoveryproviders", "cluster"),
]

RAPIDAST_REPO = "https://github.com/RedHatProductSecurity/rapidast.git"
RAPIDAST_DIR = "rapidast"
CONFIG_DIR = "Cr-Configs"
RESULT_BASE_DIR = "Dastscan-op"
OOBTKUBE_SCRIPT = "scanners/generic/tools/oobtkube.py"


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


def ensure_rapidast(script_dir, download=False):
    """Ensure rapidast exists. Clone from GitHub only if not present. Never re-download."""
    rapidast_path = script_dir / RAPIDAST_DIR
    oobtkube_path = rapidast_path / OOBTKUBE_SCRIPT

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

    print(f"  Cloning RapiDAST from {RAPIDAST_REPO}...")
    result = subprocess.run(
        f"git clone {RAPIDAST_REPO} {rapidast_path}",
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

    # Check oc is available
    try:
        run_cmd("oc version", check=True)
        print("  [OK] oc CLI available")
    except Exception:
        print("  [FAIL] oc CLI not found or not configured")
        sys.exit(1)

    # Check cluster access
    try:
        run_cmd("oc whoami", check=True)
        print("  [OK] Cluster access verified")
    except Exception:
        print("  [FAIL] Cannot access cluster. Check KUBECONFIG.")
        sys.exit(1)

    # Check namespace exists
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

    # Check pods are running
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


def export_crs(namespace, config_dir):
    """Export all CRs from cluster."""
    print("=" * 60)
    print("Step 2: Exporting CRs from cluster...")
    print("=" * 60)

    config_dir.mkdir(parents=True, exist_ok=True)

    for plural, cr_name in CR_CONFIGS:
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


def run_oobtkube_scans(callback_ip, duration, port, config_dir, result_dir, rapidast_path):
    """Run OOBTKUBE for each CR config."""
    print("=" * 60)
    print("Step 3: Running OOBTKUBE scans...")
    print("=" * 60)

    oobtkube_script = rapidast_path / OOBTKUBE_SCRIPT
    config_files = list(config_dir.glob("*.yaml"))

    if not config_files:
        print("  [FAIL] No YAML files found in Cr-Configs/")
        sys.exit(1)

    for config_file in sorted(config_files):
        base = config_file.stem
        output_file = result_dir / f"oobtkube-{base}-results.sarif"

        print(f"  Scanning: {config_file.name} -> {output_file.name}")

        cmd = [
            sys.executable,
            str(oobtkube_script),
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
        description="Automate DAST scanning for ZTWIM operator on OpenShift"
    )
    parser.add_argument(
        "--namespace",
        default="zero-trust-workload-identity-manager",
        help="Operator namespace",
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

    # Ensure RapiDAST exists (clone if --download-rapidast or already exists)
    print("=" * 60)
    print("Step 0: Ensuring RapiDAST is available...")
    print("=" * 60)
    rapidast_path = ensure_rapidast(script_dir, download=args.download_rapidast)
    print()

    callback_ip = args.callback_ip or get_callback_ip()
    if not callback_ip:
        print("Error: Could not determine callback IP. Use --callback-ip.")
        sys.exit(1)

    # Create timestamped result directory
    timestamp = get_timestamp_dir()
    result_dir = script_dir / RESULT_BASE_DIR / timestamp
    result_dir.mkdir(parents=True, exist_ok=True)
    config_dir = script_dir / CONFIG_DIR

    print(f"Using callback IP: {callback_ip}")
    print(f"Result directory: {result_dir}")
    print(f"Ensure firewall allows port {args.port}: sudo firewall-cmd --add-port={args.port}/tcp")
    print()

    check_prerequisites(args.namespace)

    # Precheck: restore CRs from previous run so cluster is clean before scan
    restore_crs(args.namespace, config_dir)

    if not args.skip_export:
        export_crs(args.namespace, config_dir)
    else:
        print("Skipping CR export (--skip-export). Using existing Cr-Configs/")
        config_dir.mkdir(parents=True, exist_ok=True)

    run_oobtkube_scans(
        callback_ip, args.duration, args.port,
        config_dir, result_dir, rapidast_path
    )
    print_summary(result_dir)

    print("Done.")
    print(f"Results saved to: {result_dir}")


if __name__ == "__main__":
    main()
