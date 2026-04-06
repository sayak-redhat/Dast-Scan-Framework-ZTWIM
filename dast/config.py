"""Config loading and helpers for DAST scan automation."""

from pathlib import Path

# Unified layout: config/operators/<operator>/oobtkube.yaml and zap/zap.yaml
OPERATORS_CONFIG_ROOT = "config/operators"

# Unified results: results/oobtkube/..., results/zap/{flat,rapidast}/..., results/trivy/...
OOBTKUBE_RESULTS_BASE = "results/oobtkube"
ZAP_RAPIDAST_BASE = "results/zap/rapidast"
ZAP_FLAT_BASE = "results/zap/flat"
TRIVY_RAPIDAST_BASE = "results/trivy/rapidast"
TRIVY_FLAT_BASE = "results/trivy/flat"


def operator_oobtkube_config(script_dir, operator_name):
    """Path to config/operators/<operator>/oobtkube.yaml."""
    return Path(script_dir) / OPERATORS_CONFIG_ROOT / operator_name / "oobtkube.yaml"


def operator_zap_config(script_dir, operator_name):
    """Path to config/operators/<operator>/zap/zap.yaml."""
    return Path(script_dir) / OPERATORS_CONFIG_ROOT / operator_name / "zap" / "zap.yaml"


def operator_zap_dir(script_dir, operator_name):
    """Directory containing zap-operator.yaml and zap-operands.yaml."""
    return Path(script_dir) / OPERATORS_CONFIG_ROOT / operator_name / "zap"


def operator_trivy_config(script_dir, operator_name):
    """Path to config/operators/<operator>/trivy/trivy.yaml (orchestration)."""
    return Path(script_dir) / OPERATORS_CONFIG_ROOT / operator_name / "trivy" / "trivy.yaml"

try:
    import yaml
except ImportError:
    yaml = None


def load_config(config_path):
    """Load YAML config from path. Return dict or empty dict."""
    config_path = Path(config_path)
    if not config_path.exists():
        return {}
    if yaml is None:
        return {}
    try:
        with open(config_path) as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        print(f"  [WARN] Could not load {config_path}: {e}")
        return {}


def get_operator(config, default="ztwim"):
    """Extract operator name from config."""
    return config.get("operator", default)


def get_gcs_config(config):
    """Extract GCS config from config.config.googleCloudStorage."""
    return config.get("config", {}).get("googleCloudStorage", {})


def get_app_name(config, default=None):
    """Extract application shortName for GCS export. Returns default if neither shortName nor ProductName set."""
    v = (
        config.get("application", {}).get("shortName")
        or config.get("application", {}).get("ProductName")
    )
    return v or default
