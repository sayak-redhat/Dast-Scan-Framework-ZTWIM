"""ZAP scan logic for DAST automation."""

import os
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

try:
    import yaml
except ImportError:
    yaml = None

from .utils import run_cmd, get_timestamp_dir

RESULTS_BASE = "zap-op"
RAPIDAST_IMAGE = "quay.io/redhatproductsecurity/rapidast:latest"
DAST_PREFIX = "DAST-"
RAPIDAST_PREFIX = "RapiDAST-"


def get_zap_configs(config, script_dir, operator_name):
    """Get list of ZAP config file paths. From zap.configs or default by operator name."""
    zap_section = config.get("zap") or {}
    configs = zap_section.get("configs")
    if configs:
        return [script_dir / c if not Path(c).is_absolute() else Path(c) for c in configs]
    zap_dir = script_dir / "config" / "zap"
    defaults = [
        zap_dir / f"{operator_name}-operator.yaml",
        zap_dir / f"{operator_name}-operands.yaml",
    ]
    return [p for p in defaults if p.exists()]


def get_output_names(config, num_configs):
    """Get output filenames for each scan. Default: zap-operator-results.sarif, zap-operands-results.sarif."""
    names = (config.get("zap") or {}).get("outputNames")
    if names and len(names) >= num_configs:
        return names[:num_configs]
    return [f"zap-{t}-results.sarif" for t in ("operator", "operands")][:num_configs]


def update_zap_config(config_path, api_server, token):
    """Update ZAP config YAML with API URL and token."""
    config_path = Path(config_path)
    with open(config_path) as f:
        data = yaml.safe_load(f) or {}

    if "application" not in data:
        data["application"] = {}
    data["application"]["url"] = api_server.rstrip("/")

    api_url = (
        data.get("scanners", {})
        .get("zap", {})
        .get("apiScan", {})
        .get("apis", {})
        .get("apiUrl", "")
    )
    if api_url:
        parsed = urlparse(api_url)
        path = parsed.path or "/openapi/v3/apis"
        new_api_url = api_server.rstrip("/") + path
    else:
        new_api_url = api_server.rstrip("/") + "/openapi/v3/apis"
    if "scanners" not in data:
        data["scanners"] = {}
    if "zap" not in data["scanners"]:
        data["scanners"]["zap"] = {}
    if "apiScan" not in data["scanners"]["zap"]:
        data["scanners"]["zap"]["apiScan"] = {}
    if "apis" not in data["scanners"]["zap"]["apiScan"]:
        data["scanners"]["zap"]["apiScan"]["apis"] = {}
    data["scanners"]["zap"]["apiScan"]["apis"]["apiUrl"] = new_api_url

    if "general" not in data:
        data["general"] = {}
    if "authentication" not in data["general"]:
        data["general"]["authentication"] = {"type": "http_header", "parameters": {}}
    if "parameters" not in data["general"]["authentication"]:
        data["general"]["authentication"]["parameters"] = {}
    data["general"]["authentication"]["parameters"]["name"] = "Authorization"
    data["general"]["authentication"]["parameters"]["value"] = f"Bearer {token}"

    with open(config_path, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)


def update_zap_configs(config_paths, api_server, token):
    """Update all ZAP config files with API URL and token."""
    print("=" * 60)
    print("Step 2: Updating ZAP configs with API URL and token...")
    print("=" * 60)

    for p in config_paths:
        try:
            update_zap_config(p, api_server, token)
            print(f"  [OK] Updated {p.name}")
        except Exception as e:
            print(f"  [FAIL] {p.name}: {e}")
            sys.exit(1)
    print()


def get_latest_rapidast_dir(parent_dir):
    """Find latest DAST-*-RapiDAST-* subdir in parent. Return Path or None."""
    parent = Path(parent_dir)
    if not parent.exists():
        return None
    subdirs = [
        d for d in parent.iterdir()
        if d.is_dir() and d.name.startswith(DAST_PREFIX) and RAPIDAST_PREFIX in d.name
    ]
    if not subdirs:
        return None
    subdirs.sort(key=lambda d: d.name, reverse=True)
    return subdirs[0]


def get_rapidast_parent_dir(results_base, config_path):
    """Get RapiDAST output parent dir from config shortName."""
    with open(config_path) as f:
        data = yaml.safe_load(f) or {}
    short_name = data.get("application", {}).get("shortName", "")
    if short_name:
        return results_base / short_name
    return None


def run_zap_scans(config_paths, results_base, timestamp_dir, output_names, runtime, image, timeout_minutes=90):
    """
    Run RapiDAST for each ZAP config. After each scan, copy rapidast-scan-results.sarif
    into timestamp_dir/ with the appropriate output name.
    Operator scans (61+ URLs, active scan) can take 45-60+ min; operands typically 5-30 min.
    """
    print("=" * 60)
    print("Step 3: Running ZAP scans...")
    print("=" * 60)

    results_base = Path(results_base)
    timestamp_dir = Path(timestamp_dir)
    timestamp_dir.mkdir(parents=True, exist_ok=True)
    timeout_sec = int(timeout_minutes) * 60

    try:
        os.chmod(results_base, 0o777)
    except OSError:
        pass

    for i, config_path in enumerate(config_paths):
        config_path = Path(config_path)
        output_name = output_names[i] if i < len(output_names) else f"zap-scan-{i}-results.sarif"
        print(f"  Scanning: {config_path.name} -> {output_name}")
        print(f"    (RapiDAST may take 10-60 min; timeout: {timeout_minutes} min)")

        cmd = [
            runtime,
            "run",
            "--rm",
            "-v",
            f"{config_path.resolve()}:/opt/rapidast/config/config.yaml:Z",
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
            print(f"    [WARN] Timeout ({timeout_minutes} min) - increase zap.timeoutMinutes in config if needed")
        except Exception as e:
            print(f"    [FAIL] {e}")

        parent_dir = get_rapidast_parent_dir(results_base, config_path)
        if parent_dir:
            latest = get_latest_rapidast_dir(parent_dir)
            if latest:
                sarif_src = latest / "rapidast-scan-results.sarif"
                if sarif_src.exists():
                    dest = timestamp_dir / output_name
                    shutil.copy2(sarif_src, dest)
                    print(f"    [OK] Copied to {dest.relative_to(results_base)}")
                else:
                    print(f"    [WARN] SARIF not found in {latest}")
            else:
                print(f"    [WARN] No result dir in {parent_dir}")
        else:
            print(f"    [WARN] Could not determine RapiDAST output dir")

    print()


def print_summary(result_dir):
    """Print summary of ZAP results."""
    print("=" * 60)
    print("Step 4: Summary")
    print("=" * 60)

    result_files = list(Path(result_dir).glob("*.sarif"))
    if not result_files:
        print("  No result files found.")
        return

    print(f"  Results stored in: {result_dir}")
    for f in sorted(result_files):
        size = f.stat().st_size
        print(f"    - {f.name} ({size} bytes)")

    print()
    print(f"  To view: cat {result_dir}/zap-*-results.sarif | jq .")
    print()


def get_zap_scan_dirs(zap_config_path, script_dir):
    """Get ZAP scan dir names (ZTWIM-Operator-ZAP, etc.) from ZAP config files."""
    from .config import load_config

    config = load_config(zap_config_path)
    zap_section = config.get("zap") or {}
    configs = zap_section.get("configs")
    if not configs:
        return ["ZTWIM-Operator-ZAP", "ZTWIM-Operands-ZAP"]
    dirs = []
    for c in configs:
        cfg_path = script_dir / c if not Path(c).is_absolute() else Path(c)
        if cfg_path.exists():
            with open(cfg_path) as f:
                data = yaml.safe_load(f) or {}
            short_name = data.get("application", {}).get("shortName")
            if short_name:
                dirs.append(short_name)
    return dirs if dirs else ["ZTWIM-Operator-ZAP", "ZTWIM-Operands-ZAP"]
