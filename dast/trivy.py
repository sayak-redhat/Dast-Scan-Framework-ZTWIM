"""Trivy (RapiDAST generic_trivy) scan helpers."""

import os
import shutil
import subprocess
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

from .config import load_config
from .zap import get_latest_rapidast_dir, get_rapidast_parent_dir


def get_trivy_k8s_config_path(orchestration_path, script_dir):
    """Resolve path to trivy-k8s.yaml from trivy.yaml."""
    orch = load_config(orchestration_path)
    rel = (orch.get("trivy") or {}).get("config")
    if not rel:
        return None
    p = Path(rel)
    if p.is_absolute():
        return p
    return script_dir / p


def get_trivy_short_name(k8s_config_path):
    """application.shortName from trivy-k8s.yaml."""
    data = load_config(k8s_config_path)
    return (data.get("application") or {}).get("shortName", "")


def run_trivy_scan(
    k8s_config_path,
    results_base,
    timestamp_dir,
    runtime,
    image,
    timeout_minutes=45,
    script_dir=None,
    kubeconfig_path=None,
    flat_sarif_name="trivy-k8s-results.sarif",
):
    """
    Run RapiDAST once with a generic_trivy config. Mount kubeconfig at /opt/rapidast/.kube/config.
    Copy rapidast-scan-results.sarif into timestamp_dir as flat_sarif_name.
    """
    k8s_config_path = Path(k8s_config_path)
    results_base = Path(results_base)
    timestamp_dir = Path(timestamp_dir)
    timestamp_dir.mkdir(parents=True, exist_ok=True)
    # Podman bind mounts require the host path to exist (else: statfs ... no such file or directory)
    results_base.mkdir(parents=True, exist_ok=True)
    timeout_sec = int(timeout_minutes) * 60

    kc = kubeconfig_path or os.environ.get("KUBECONFIG")
    if not kc:
        kc = str(Path.home() / ".kube" / "config")
    kc = str(Path(kc).expanduser().resolve())
    if not Path(kc).is_file():
        print(f"  [FAIL] Kubeconfig not found: {kc}")
        print("       Set KUBECONFIG or pass --kubeconfig to automate_trivy_scan.py")
        return False

    try:
        os.chmod(results_base, 0o777)
    except OSError:
        pass

    print(f"  Scanning: {k8s_config_path.name} -> {flat_sarif_name}")
    print(f"    Kubeconfig: {kc}")
    print(f"    (timeout: {timeout_minutes} min)")

    cmd = [
        runtime,
        "run",
        "--rm",
        "-v",
        f"{k8s_config_path.resolve()}:/opt/rapidast/config/config.yaml:Z",
        "-v",
        # :Z for SELinux (Fedora/RHEL); without it, open() can EPERM inside the container
        f"{kc}:/opt/rapidast/.kube/config:ro,Z",
        "-v",
        f"{results_base.resolve()}:/opt/rapidast/results/:Z",
        image,
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=False,
            text=True,
            timeout=timeout_sec,
        )
        if result.returncode != 0:
            print(f"    [WARN] Exit code {result.returncode}")
        else:
            print(f"    [OK] Completed")
    except subprocess.TimeoutExpired:
        print(f"    [WARN] Timeout ({timeout_minutes} min) — increase trivy.timeoutMinutes in config")
    except Exception as e:
        print(f"    [FAIL] {e}")
        return False

    parent_dir = get_rapidast_parent_dir(results_base, k8s_config_path)
    if parent_dir:
        latest = get_latest_rapidast_dir(parent_dir)
        if latest:
            sarif_src = latest / "rapidast-scan-results.sarif"
            if sarif_src.exists():
                dest = timestamp_dir / flat_sarif_name
                shutil.copy2(sarif_src, dest)
                _rel = (
                    dest.relative_to(script_dir)
                    if script_dir is not None
                    else dest
                )
                print(f"    [OK] Copied to {_rel}")
                return True
            print(f"    [WARN] SARIF not found in {latest}")
        else:
            print(f"    [WARN] No DAST-* dir under {parent_dir}")
    else:
        print(f"    [WARN] Could not determine RapiDAST output dir")
    return False


def print_trivy_summary(result_dir):
    """Print summary of Trivy flat results."""
    result_dir = Path(result_dir)
    result_files = sorted(result_dir.glob("*.sarif"))
    if not result_files:
        print("  No Trivy SARIF in flat dir.")
        return
    print(f"  Trivy flat results: {result_dir}")
    for f in result_files:
        print(f"    - {f.name} ({f.stat().st_size} bytes)")
