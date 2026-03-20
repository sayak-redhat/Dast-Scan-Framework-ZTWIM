#!/bin/bash
# Update ZAP configs with current cluster API URL and token.
# Run before each ZAP scan (tokens expire ~1 hour; CI clusters are ephemeral).
#
# Usage: ./scripts/update-zap-config.sh
#        Or: bash scripts/update-zap-config.sh

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_DIR="$REPO_ROOT/config/zap"

API_SERVER=$(oc cluster-info 2>/dev/null | grep "Kubernetes control plane" | awk '{print $NF}')
TOKEN=$(oc create token default -n default 2>/dev/null)

if [ -z "$API_SERVER" ] || [ -z "$TOKEN" ]; then
  echo "Error: Could not get API URL or token. Ensure 'oc' is configured and you're logged in."
  echo "  oc cluster-info"
  echo "  oc create token default -n default"
  exit 1
fi

echo "Updating ZAP configs with API: $API_SERVER"
for f in "$CONFIG_DIR"/ztwim-operator.yaml "$CONFIG_DIR"/ztwim-operands.yaml; do
  if [ -f "$f" ]; then
    sed -i "s|<API_SERVER>|${API_SERVER}|g" "$f"
    # Use # delimiter so / and . in JWT token don't break sed
    sed -i "s#<TOKEN>#${TOKEN}#g" "$f"
    echo "  Updated: $f"
  fi
done
echo "Done. Run the ZAP scan now (token expires in ~1 hour)."
