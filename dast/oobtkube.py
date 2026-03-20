"""OOBTKUBE scan logic for DAST automation."""

import shutil
import subprocess
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

from .utils import run_cmd, get_timestamp_dir


def get_framework(config):
    """Extract framework settings with defaults."""
    fw = config.get("framework") or {}
    return {
        "rapidastRepo": fw.get("rapidastRepo", "https://github.com/RedHatProductSecurity/rapidast.git"),
        "rapidastDir": fw.get("rapidastDir", "rapidast"),
        "configDir": fw.get("configDir", "Cr-Configs"),
        "resultBaseDir": fw.get("resultBaseDir", "oobtkube-op"),
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


def ensure_rapidast(script_dir, framework, download=False):
    """Ensure rapidast exists. Clone from GitHub only if not present."""
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
        cwd=str(script_dir),
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


def migrate_flat_config_to_operator_dir(config_dir, cr_configs):
    """One-time migration: move CR files from flat Cr-Configs/ to Cr-Configs/<operator>/."""
    config_dir = Path(config_dir)
    base_dir = config_dir.parent
    expected = {f"{plural}-cr-oobtkube.yaml" for plural, _ in cr_configs} if cr_configs else set()
    if not expected:
        return

    op_files = list(config_dir.glob("*-cr-oobtkube.yaml")) if config_dir.exists() else []
    flat_files = list(base_dir.glob("*-cr-oobtkube.yaml"))
    to_migrate = [f for f in flat_files if f.name in expected and f.parent == base_dir]

    if not op_files and to_migrate:
        config_dir.mkdir(parents=True, exist_ok=True)
        for f in to_migrate:
            dest = config_dir / f.name
            shutil.move(str(f), str(dest))
            print(f"  [MIGRATE] Moved {f.name} -> {config_dir.name}/")


def restore_crs(namespace, config_dir):
    """Restore CRs to clean state from Cr-Configs (from previous run)."""
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
            if result.returncode != 0 or not out or "Error from server" in out or "NotFound" in out:
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
    config_files = sorted(config_dir.glob("*-cr-oobtkube.yaml"))

    if not config_files:
        print(f"  [FAIL] No CR config files (*-cr-oobtkube.yaml) found in {config_dir}")
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
