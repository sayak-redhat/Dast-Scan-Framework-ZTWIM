"""Config loading and helpers for DAST scan automation."""

from pathlib import Path

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
