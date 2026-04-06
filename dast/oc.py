"""OpenShift/oc CLI helpers for DAST scan automation."""

import os
import subprocess
import sys
from pathlib import Path

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


def apply_zap_token_env_defaults(zap_section):
    """
    Apply service account / namespace from ZAP orchestration YAML (e.g. config/operators/ztwim/zap/zap.yaml)
    when ZAP_SERVICE_ACCOUNT / ZAP_TOKEN_NAMESPACE are not already set. Environment variables win.

    Supported keys under zap: serviceAccount | service_account, tokenNamespace | token_namespace
    """
    if not isinstance(zap_section, dict):
        return
    sa = zap_section.get("serviceAccount") or zap_section.get("service_account")
    ns = zap_section.get("tokenNamespace") or zap_section.get("token_namespace")
    if sa and not (os.environ.get("ZAP_SERVICE_ACCOUNT") or "").strip():
        os.environ["ZAP_SERVICE_ACCOUNT"] = str(sa).strip()
    if ns and not (os.environ.get("ZAP_TOKEN_NAMESPACE") or "").strip():
        os.environ["ZAP_TOKEN_NAMESPACE"] = str(ns).strip()


def resolve_zap_sa_and_ns(zap_section=None):
    """
    Service account and namespace for `oc create token` (ZAP Kubernetes API scans).

    Priority: non-empty ZAP_SERVICE_ACCOUNT / ZAP_TOKEN_NAMESPACE env vars, then
    zap.serviceAccount / zap.tokenNamespace from orchestration YAML, then default/default.

    Use this (or pass zap_section into get_api_url_and_token) so runtime token creation
    always reflects zap.yaml when env vars are not explicitly set.
    """
    yaml_sa = yaml_ns = None
    if isinstance(zap_section, dict):
        yaml_sa = zap_section.get("serviceAccount") or zap_section.get("service_account")
        yaml_ns = zap_section.get("tokenNamespace") or zap_section.get("token_namespace")
    sa = (os.environ.get("ZAP_SERVICE_ACCOUNT") or "").strip() or (
        str(yaml_sa).strip() if yaml_sa else ""
    ) or "default"
    ns = (os.environ.get("ZAP_TOKEN_NAMESPACE") or "").strip() or (
        str(yaml_ns).strip() if yaml_ns else ""
    ) or "default"
    return sa, ns


def ensure_zap_cluster_bootstrap(zap_yaml_path, zap_section=None, skip=False):
    """
    Apply dast-zap-setup.yaml next to zap.yaml (namespace, ServiceAccount, RBAC) if present.

    Runs `oc apply -f` before `oc create token`. Requires permissions to create namespaces
    and ClusterRoleBindings (typically cluster-admin). Idempotent.

    Skip when: skip=True, or zap.bootstrap: false in orchestration YAML, or manifest file missing.
    """
    if skip:
        return True
    if isinstance(zap_section, dict) and zap_section.get("bootstrap") is False:
        return True

    manifest = Path(zap_yaml_path).resolve().parent / "dast-zap-setup.yaml"
    if not manifest.is_file():
        return True

    print("=" * 60)
    print("Step 1b: Cluster bootstrap (namespace + service account + RBAC)...")
    print("=" * 60)
    print(f"  Applying: {manifest}")
    proc = subprocess.run(
        ["oc", "apply", "-f", str(manifest)],
        capture_output=True,
        text=True,
    )
    out = (proc.stdout or "").strip()
    err = (proc.stderr or "").strip()
    if proc.returncode != 0:
        print(f"  [WARN] oc apply failed (exit {proc.returncode})")
        if err:
            print(f"  {err}")
        elif out:
            print(f"  {out}")
        print(
            "  You need permission to create namespaces and ClusterRoleBindings, or run manually:\n"
            f"    oc apply -f {manifest}"
        )
        print()
        return False

    if out:
        for line in out.split("\n"):
            print(f"  {line}")
    print("  [OK] Bootstrap applied (idempotent; safe to re-run)")
    print()
    return True


def _kubeconfig_path_display():
    """Path(s) `oc` uses: KUBECONFIG if set, else ~/.kube/config (matches kubectl/oc rules)."""
    kc = os.environ.get("KUBECONFIG", "").strip()
    if kc:
        return kc
    default = os.path.expanduser("~/.kube/config")
    return default if os.path.isfile(default) else "~/.kube/config"


def _oc_current_context():
    """Active context name from the kubeconfig `oc` is using."""
    return (run_cmd("oc config current-context 2>/dev/null", check=False) or "").strip()


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
    print(f"  [OK] kubeconfig (oc uses this for all cluster commands): {_kubeconfig_path_display()}")
    ctx = _oc_current_context()
    if ctx:
        print(f"  [OK] current context: {ctx}")
    print()


def get_api_url_and_token(zap_section=None):
    """
    Get API server URL and bearer token for ZAP Kubernetes API scans.

    Token resolution (first match wins):
      1. ZAP_KUBERNETES_TOKEN or RAPIDAST_TOKEN — use as-is (e.g. export ZAP_KUBERNETES_TOKEN=$(oc whoami -t))
      2. Otherwise: oc create token <sa> -n <ns> on the cluster from your kubeconfig
         (export KUBECONFIG=... or use ~/.kube/config; same cluster as oc whoami / current context).
         Identity comes from ZAP_SERVICE_ACCOUNT / ZAP_TOKEN_NAMESPACE or zap_section in YAML.
      3. zap.yaml serviceAccount / tokenNamespace when env vars are unset.
      4. Fallback: default/default (often yields 403; see docs/ZAP-RBAC-and-Review-Notes.md)

    API URL: oc cluster-info (override with ZAP_API_SERVER if set).

    Orchestration YAML (config/operators/<operator>/zap/zap.yaml) may set zap.serviceAccount and zap.tokenNamespace;
    pass zap_section so those are used at runtime when env vars are unset (see resolve_zap_sa_and_ns).
    """
    api_server = os.environ.get("ZAP_API_SERVER")
    if not api_server:
        api_server = run_cmd(
            "oc cluster-info 2>/dev/null | grep 'Kubernetes control plane' | awk '{print $NF}'",
            check=False,
        )
    api_server = (api_server or "").strip()

    sa, ns = resolve_zap_sa_and_ns(zap_section)
    token = (os.environ.get("ZAP_KUBERNETES_TOKEN") or os.environ.get("RAPIDAST_TOKEN") or "").strip()
    token_from_env = bool(token)

    if not token:
        # Bound token for the service account on the *current* OpenShift cluster (active kubeconfig context).
        proc = subprocess.run(
            ["oc", "create", "token", sa, "-n", ns],
            capture_output=True,
            text=True,
        )
        token = (proc.stdout or "").strip()
        if token:
            cluster_server = run_cmd("oc whoami --show-server 2>/dev/null", check=False)
            cluster_server = (cluster_server or "").strip()
            ctx = _oc_current_context()
            print("  [OK] Created SA token on the cluster from your kubeconfig (running oc session).")
            print(f"  [OK] kubeconfig: {_kubeconfig_path_display()}")
            if ctx:
                print(f"  [OK] current context: {ctx}")
            if cluster_server:
                print(f"  [OK] API server: {cluster_server}")
            print(f"  [OK] oc create token {sa} -n {ns}")
        else:
            cluster_server = run_cmd("oc whoami --show-server 2>/dev/null", check=False)
            cluster_server = (cluster_server or "").strip()
            ctx = _oc_current_context()
            print("Error: Could not create a service account token on the OpenShift cluster.")
            print(f"  kubeconfig in use: {_kubeconfig_path_display()}")
            if ctx:
                print(f"  current context: {ctx}")
            if cluster_server:
                print(f"  Active API server: {cluster_server}")
            print(f"  Command run: oc create token {sa} -n {ns}")
            if proc.stderr:
                print(f"  {proc.stderr.strip()}")
            print("  Ensure you are logged in (oc login) and the SA exists with permission to create tokens.")
            print("  Or use an explicit token: export ZAP_KUBERNETES_TOKEN=$(oc whoami -t)")
            sys.exit(1)

    if not api_server or not token:
        print("Error: Could not get API URL or token.")
        print("  Ensure 'oc' is configured and you're logged in.")
        print("  Options:")
        print("    export ZAP_KUBERNETES_TOKEN=$(oc whoami -t)   # use your user token (needs API access)")
        print("    export ZAP_SERVICE_ACCOUNT=dast-zap ZAP_TOKEN_NAMESPACE=ztwim-dast   # dedicated SA with RBAC")
        print("    oc cluster-info && oc create token default -n default")
        sys.exit(1)

    if not token_from_env and sa == "default" and ns == "default":
        print("  [WARN] Using default/default service account token. Most API paths return 403 unless")
        print("         that SA has RBAC to list/get the target APIs. Set ZAP_KUBERNETES_TOKEN=$(oc whoami -t)")
        print("         or a dedicated SA — see docs/ZAP-RBAC-and-Review-Notes.md")
        print()

    return api_server, token


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
