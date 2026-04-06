#!/usr/bin/env bash
# Remove local scan artifacts, exported CRs, RapiDAST clone, caches, and stray key files.
# Safe to run before commits; does not touch config/, source, or .venv.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "Cleaning under $ROOT ..."

# results/ covers results/oobtkube, results/zap, results/trivy, etc.
rm -rf results oobtkube-op rapidast \
  __pycache__ dast/__pycache__ scripts/__pycache__ exports/__pycache__
# oobtkube-config/<operator>/ is gitignored; keep tracked oobtkube-config/README.md
if [[ -d oobtkube-config ]]; then
  find oobtkube-config -mindepth 1 -maxdepth 1 ! -name README.md -exec rm -rf {} +
fi
rm -f run_all_err.txt *.err 2>/dev/null || true
# GCS key files live in secrets/ (gitignored); also clean any stray ones at root
rm -rf secrets/ 2>/dev/null || true
rm -f rapidast-sa-operators-*.json *_key.json 2>/dev/null || true

if [[ -d zap-op ]]; then
  if rm -rf zap-op 2>/dev/null; then
    echo "  Removed zap-op/"
  elif command -v podman >/dev/null 2>&1; then
    echo "  zap-op/ not removable as normal user (Podman volume perms); trying podman unshare ..."
    podman unshare rm -rf "$ROOT/zap-op" && echo "  Removed zap-op/"
  else
    echo "  Could not remove zap-op/. Install podman and run: podman unshare rm -rf \"$ROOT/zap-op\""
    echo "  Or: sudo rm -rf \"$ROOT/zap-op\""
    exit 1
  fi
fi

echo "Done."
