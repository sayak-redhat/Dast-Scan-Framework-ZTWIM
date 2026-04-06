#!/bin/bash
# DEPRECATED: automate_zap_scan.py now injects tokens into a temporary directory
# at runtime and auto-cleans them after the scan.  On-disk templates are never
# modified, so this script is no longer needed.
#
# If you still want to manually patch templates for one-off debugging, this
# script works — but the tokens will end up on disk (risk of accidental commit).
#
# Preferred workflow:
#   python3 scripts/automate_zap_scan.py --config config/operators/ztwim/zap/zap.yaml
#
# Legacy usage: ./scripts/update-zap-config.sh

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_DIR="$REPO_ROOT/config/operators/ztwim/zap"

API_SERVER=$(oc cluster-info 2>/dev/null | grep "Kubernetes control plane" | awk '{print $NF}')
TOKEN=$(oc create token default -n default 2>/dev/null)

if [ -z "$API_SERVER" ] || [ -z "$TOKEN" ]; then
  echo "Error: Could not get API URL or token. Ensure 'oc' is configured and you're logged in."
  echo "  oc cluster-info"
  echo "  oc create token default -n default"
  exit 1
fi

echo "Updating ZAP configs with API: $API_SERVER"
for f in "$CONFIG_DIR"/zap-operator.yaml "$CONFIG_DIR"/zap-operands.yaml; do
  if [ -f "$f" ]; then
    sed -i "s|<API_SERVER>|${API_SERVER}|g" "$f"
    # Use # delimiter so / and . in JWT token don't break sed
    sed -i "s#<TOKEN>#${TOKEN}#g" "$f"
    echo "  Updated: $f"
  fi
done
echo "Done. Run the ZAP scan now (token expires in ~1 hour)."
