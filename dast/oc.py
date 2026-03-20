"""OpenShift/oc CLI helpers for DAST scan automation."""

import subprocess
import sys

from .utils import run_cmd


def _verify_oc():
    """Verify oc CLI is available."""
    try:
        run_cmd("oc version", check=True)
        print("  [OK] oc CLI available")
    except Exception:
        print("  [FAIL] oc CLI not found or not configured")
        sys.exit(1)


def _verify_cluster():
    """Verify cluster access via oc whoami."""
    try:
        run_cmd("oc whoami", check=True)
        print("  [OK] Cluster access verified")
    except Exception:
        print("  [FAIL] Cannot access cluster. Check KUBECONFIG.")
        sys.exit(1)


def _verify_namespace(namespace):
    """Verify namespace exists."""
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
        print("  [FAIL] Namespace check failed")
        sys.exit(1)


def _verify_pods(namespace):
    """Optionally verify pods in namespace (warning only)."""
    try:
        out = run_cmd(f"oc get pods -n {namespace} --no-headers 2>/dev/null", check=False)
        pods = [line for line in (out or "").split("\n") if line and "Running" in line]
        if len(pods) < 3:
            print(f"  [WARN] Few pods running ({len(pods)}). Operator may not be fully ready.")
        else:
            print(f"  [OK] {len(pods)} pods running in namespace")
    except Exception:
        print("  [WARN] Could not verify pods")


def check_oc_prerequisites(namespace=None):
    """Verify oc CLI and cluster access. Optionally check namespace and pods (for OOBTKUBE)."""
    print("=" * 60)
    print("Step 1: Checking prerequisites...")
    print("=" * 60)
    _verify_oc()
    _verify_cluster()
    if namespace:
        _verify_namespace(namespace)
        _verify_pods(namespace)
    print()


def check_zap_prerequisites():
    """Verify oc, container runtime, and cluster access (for ZAP scans)."""
    print("=" * 60)
    print("Step 1: Checking prerequisites...")
    print("=" * 60)
    _verify_oc()
    runtime = get_container_runtime()
    if not runtime:
        print("  [FAIL] Neither podman nor docker found")
        sys.exit(1)
    print(f"  [OK] Container runtime: {runtime}")
    _verify_cluster()
    print()


def get_api_url_and_token():
    """Get API server URL and bearer token via oc. Returns (url, token) or exits."""
    api_server = run_cmd(
        "oc cluster-info 2>/dev/null | grep 'Kubernetes control plane' | awk '{print $NF}'",
        check=False,
    )
    token = run_cmd(
        "oc create token default -n default 2>/dev/null",
        check=False,
    )
    if not api_server or not token:
        print("Error: Could not get API URL or token.")
        print("  Ensure 'oc' is configured and you're logged in.")
        print("  oc cluster-info")
        print("  oc create token default -n default")
        sys.exit(1)
    return api_server.strip(), token.strip()


def get_container_runtime():
    """Return 'podman' or 'docker' depending on availability."""
    for runtime in ("podman", "docker"):
        try:
            subprocess.run(
                [runtime, "version"],
                capture_output=True,
                check=True,
            )
            return runtime
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue
    return None
