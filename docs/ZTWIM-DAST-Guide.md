# ZTWIM DAST Guide

Complete guide for DAST scanning the Zero Trust Workload Identity Manager (ZTWIM) operator: OOBTKUBE (command injection) and ZAP (API security).

---

## Table of Contents

1. [Two Ways to Test ZTWIM](#1-two-ways-to-test-ztwim)
2. [Part 1: OOBTKUBE (Command Injection)](#2-part-1-oobtkube-command-injection)
3. [Part 2: ZAP API Scanning](#3-part-2-zap-api-scanning)
   - [Prerequisites](#31-prerequisites)
   - [Automated ZAP Scan](#32-automated-zap-scan-recommended)
   - [Get API Server URL and Token](#33-get-api-server-url-and-token-manual)
   - [ZTWIM API Groups](#34-ztwim-api-groups)
   - [Create ZAP Config](#35-create-zap-config-manual)
   - [Run ZAP Scan](#36-run-zap-scan-manual)
   - [View Results](#37-view-results)
   - [Upload to GCP](#38-upload-to-gcp)
   - [Helm (in-cluster)](#39-helm-in-cluster)
4. [Quick Reference](#4-quick-reference)
5. [Checklist](#5-checklist)
6. [Troubleshooting](#6-troubleshooting)

---

## 1. Two Ways to Test ZTWIM

| Approach | What it tests | Tool |
|----------|---------------|------|
| **OOBTKUBE** | Command injection via CR reconciliation | `scripts/automate_dast_scan.py` |
| **ZAP** | HTTP/API security of ZTWIM's API groups | `scripts/automate_zap_scan.py` |

### Run Both and Upload Combined to GCS

Use `run_all_dast_scans.py` to run OOBTKUBE and ZAP, then upload a single tarball containing all results:

```bash
python3 run_all_dast_scans.py --config config/oobtkube/ztwim.yaml --callback-ip <YOUR_IP>
```

The tarball includes `oobtkube-op/ztwim/<timestamp>/`, `zap-op/ZTWIM-Operator-ZAP/DAST-*/`, and `zap-op/ZTWIM-Operands-ZAP/DAST-*/`, uploaded to `gs://{bucket}/operators/ztwim/{timestamp}-RapiDAST-ZTWIM-DAST-{random}.tgz`.

---

## 2. Part 1: OOBTKUBE (Command Injection)

### Prerequisites

- OpenShift cluster with ZTWIM installed
- ZTWIM running in namespace `zero-trust-workload-identity-manager`
- Callback IP reachable from cluster pods (your machine's IP)
- Port 12345 open: `sudo firewall-cmd --add-port=12345/tcp`
- RapiDAST cloned (use `--download-rapidast` on first run)

### Steps

1. **Verify ZTWIM is running**
   ```bash
   oc get pods -n zero-trust-workload-identity-manager
   oc get zerotrustworkloadidentitymanagers,spireservers,spireagents -n zero-trust-workload-identity-manager
   ```

2. **Run the scan**
   ```bash
   cd dast-scan-automation
   pip install -r requirements.txt
   python3 scripts/automate_dast_scan.py --config config/oobtkube/ztwim.yaml --download-rapidast --callback-ip <YOUR_IP>
   ```

3. **What happens**
   - CRs are exported from the cluster to `Cr-Configs/ztwim/`
   - OOBTKUBE runs for each CR (zerotrustworkloadidentitymanagers, spireservers, spireagents, spiffecsidrivers, spireoidcdiscoveryproviders)
   - Each CR's spec fields are modified with a callback payload
   - If the operator executes the payload, a callback is detected and a vulnerability is reported
   - Results are written to `oobtkube-op/ztwim/<timestamp>/*.sarif`

### If CRs Don't Exist Yet

If `oc get zerotrustworkloadidentitymanagers -n zero-trust-workload-identity-manager` returns nothing, create at least one ZTWIM CR so the scan has something to test. See ZTWIM docs for how to create the initial CR.

---

## 3. Part 2: ZAP API Scanning

Scans the ZTWIM Kubernetes API groups for HTTP-level issues (e.g. error disclosure). ZTWIM has two API groups; run separate scans for each.

### 3.1 Prerequisites

- OpenShift cluster with ZTWIM operator and operands installed
- **oc CLI** configured and logged in (`oc login` or `KUBECONFIG` set)
- **Podman** installed on your machine
- **dast-scan-automation** repository cloned

Verify ZTWIM is running:

```bash
oc get pods -n zero-trust-workload-identity-manager
oc get zerotrustworkloadidentitymanagers,spireservers,spireagents -n zero-trust-workload-identity-manager
```

### 3.2 Automated ZAP Scan (Recommended)

Use `scripts/automate_zap_scan.py` to run the full ZAP workflow. Results are stored in `zap-op/<operator>/<timestamp>/` (like oobtkube-op) with flat SARIF files.

```bash
cd dast-scan-automation
pip install -r requirements.txt
python3 scripts/automate_zap_scan.py --config config/zap/ztwim.yaml
```

**Options:** `--skip-upload`, `--skip-config-update`

Results: `zap-op/ztwim/<timestamp>/zap-operator-results.sarif`, `zap-operands-results.sarif`

### 3.3 Get API Server URL and Token (Manual)

**API URL:**
```bash
oc cluster-info
# Extract: oc cluster-info | grep "Kubernetes control plane" | awk '{print $NF}'
```

**Bearer token:**
```bash
oc create token default -n default
```

**Note:** Tokens expire (typically 1 hour). Regenerate when expired. **Never commit tokens to git.**

### 3.4 ZTWIM API Groups

| API Group | Resources | Config File | OpenAPI URL |
|-----------|-----------|-------------|-------------|
| **operator.openshift.io/v1alpha1** | zerotrustworkloadidentitymanagers, spireservers, spireagents, spireoidcdiscoveryproviders, spiffecsidrivers | `config/zap/ztwim-operator.yaml` | `.../openapi/v3/apis/operator.openshift.io/v1alpha1` |
| **spire.spiffe.io/v1alpha1** | clusterfederatedtrustdomains, clusterspiffeids, clusterstaticentries | `config/zap/ztwim-operands.yaml` | `.../openapi/v3/apis/spire.spiffe.io/v1alpha1` |

### 3.5 Create ZAP Config (Manual)

The repo includes both configs with placeholders. Replace `<API_SERVER>` and `<TOKEN>` before running (required—CI clusters are ephemeral, tokens expire ~1 hour).

- **`config/zap/ztwim-operator.yaml`** — Operator CRs
- **`config/zap/ztwim-operands.yaml`** — Operands CRs (SPIFFE/SPIRE)

**Option A: Use the update script (recommended)**
```bash
./scripts/update-zap-config.sh
```

**Option B: Replace manually with sed**
```bash
API_SERVER=$(oc cluster-info | grep "Kubernetes control plane" | awk '{print $NF}')
TOKEN=$(oc create token default -n default)
sed -i "s|<API_SERVER>|${API_SERVER}|g" config/zap/ztwim-operator.yaml config/zap/ztwim-operands.yaml
sed -i "s#<TOKEN>#${TOKEN}#g" config/zap/ztwim-operator.yaml config/zap/ztwim-operands.yaml
```

### 3.6 Run ZAP Scan (Manual)

**Create results directory:**
```bash
mkdir -p zap-op && chmod o+w zap-op
```

**Operator scan:**
```bash
podman run -v $(pwd)/config/zap/ztwim-operator.yaml:/opt/rapidast/config/config.yaml:Z \
  -v $(pwd)/zap-op/:/opt/rapidast/results/:Z \
  quay.io/redhatproductsecurity/rapidast:latest
```

**Operands scan:**
```bash
podman run -v $(pwd)/config/zap/ztwim-operands.yaml:/opt/rapidast/config/config.yaml:Z \
  -v $(pwd)/zap-op/:/opt/rapidast/results/:Z \
  quay.io/redhatproductsecurity/rapidast:latest
```

Results: RapiDAST writes to `zap-op/ZTWIM-Operator-ZAP/` and `zap-op/ZTWIM-Operands-ZAP/`. When using `scripts/automate_zap_scan.py`, SARIF files are copied to `zap-op/ztwim/<timestamp>/`.

### 3.7 View Results

**With scripts/automate_zap_scan.py (recommended structure):**
```
zap-op/ztwim/2026-03-19_10-30-00/
├── zap-operator-results.sarif
└── zap-operands-results.sarif
```

**Manual runs (RapiDAST default):**
```
zap-op/ZTWIM-Operator-ZAP/DAST-<timestamp>-RapiDAST-ZTWIM-Operator-ZAP/
├── rapidast-scan-results.sarif
├── zap/zap-report.html
└── ...
```

**View SARIF:**
```bash
cat zap-op/ztwim/*/zap-*-results.sarif | jq .
```

### 3.8 Upload to GCP

ZAP results use `config/zap/ztwim.yaml` for GCS settings. Upload finds the latest `zap-op/ztwim/<timestamp>/` and uploads it.

**Prerequisites:** `google-cloud-storage` (`pip install -r requirements.txt`), service account key file

```bash
# Upload latest ZAP results
python3 exports/upload_zap_results.py --config config/zap/ztwim.yaml

# Upload all timestamped results
python3 exports/upload_zap_results.py --config config/zap/ztwim.yaml --all
```

Results are uploaded to `gs://{bucket}/{directory}/{timestamp}-RapiDAST-{app_name}-{random}.tgz` (same format as OOBTKUBE).

### 3.9 Helm (in-cluster)

```bash
git clone https://github.com/RedHatProductSecurity/rapidast.git --branch main
cd rapidast
# Operator:
helm install rapidast ./helm/chart/ --set-file rapidastConfig=../dast-scan-automation/config/zap/ztwim-operator.yaml
# Operands (after operator scan: helm uninstall rapidast, then):
helm install rapidast ./helm/chart/ --set-file rapidastConfig=../dast-scan-automation/config/zap/ztwim-operands.yaml
# Results in rapidast-pvc; use helm/results.sh to copy to local
```

---

## 4. Quick Reference

| Step | Command |
|------|---------|
| **Run both + upload combined** | `python3 run_all_dast_scans.py --config config/oobtkube/ztwim.yaml --callback-ip <IP>` |
| **Automated ZAP (recommended)** | `python3 scripts/automate_zap_scan.py --config config/zap/ztwim.yaml` |
| Update config (manual) | `./scripts/update-zap-config.sh` |
| Get API URL | `oc cluster-info` |
| Get token | `oc create token default -n default` |
| Run operator scan | `podman run -v $(pwd)/config/zap/ztwim-operator.yaml:/opt/rapidast/config/config.yaml:Z -v $(pwd)/zap-op/:/opt/rapidast/results/:Z quay.io/redhatproductsecurity/rapidast:latest` |
| Run operands scan | `podman run -v $(pwd)/config/zap/ztwim-operands.yaml:/opt/rapidast/config/config.yaml:Z -v $(pwd)/zap-op/:/opt/rapidast/results/:Z quay.io/redhatproductsecurity/rapidast:latest` |
| Upload to GCP | `python3 exports/upload_zap_results.py --config config/zap/ztwim.yaml` |

**Operator OpenAPI URL:** `https://<API_SERVER>/openapi/v3/apis/operator.openshift.io/v1alpha1`

**Operands OpenAPI URL:** `https://<API_SERVER>/openapi/v3/apis/spire.spiffe.io/v1alpha1`

---

## 5. Checklist

- [ ] ZTWIM operator installed and running
- [ ] At least one CR of each type exists (or you accept some will be skipped)
- [ ] Callback IP identified and reachable from cluster
- [ ] Port 12345 open on firewall
- [ ] RapiDAST cloned (`--download-rapidast`)
- [ ] Run: `python3 scripts/automate_dast_scan.py --config config/oobtkube/ztwim.yaml --callback-ip <IP>`
- [ ] (Optional) Run ZAP scan: `python3 scripts/automate_zap_scan.py --config config/zap/ztwim.yaml`
- [ ] (Optional) Upload ZAP results: `python3 exports/upload_zap_results.py --config config/zap/ztwim.yaml`
- [ ] (Optional) Run both + upload combined: `python3 run_all_dast_scans.py --config config/oobtkube/ztwim.yaml --callback-ip <IP>`

---

## 6. Troubleshooting

| Issue | Action |
|-------|--------|
| No CRs found | Create ZTWIM CRs per ZTWIM docs |
| Callback not received | Check firewall, ensure callback IP is reachable from pods |
| Namespace not found | Confirm ZTWIM is installed: `oc get csv -A \| grep -i ztwim` |
| RapiDAST not found | Run with `--download-rapidast` |
| `lstat config: no such file or directory` | Run from `dast-scan-automation` directory; use absolute paths if needed |
| Token expired / 401 Unauthorized | Regenerate token: `oc create token default -n default` |
| Cannot reach API server | Ensure VPN is connected; API URL must be reachable from your machine |
| Job openapi added 0 URLs | Config may point to wrong cluster. Verify API URL matches `oc cluster-info` |
| **invalid API URL** | Cluster may be gone (CI clusters are ephemeral), token expired, or API unreachable. Run `oc cluster-info` and `oc create token default -n default` to get current URL and token; update `application.url` and `scanners.zap.apiScan.apis.apiUrl` in the config |
| Podman not found | Install Podman or use Docker with equivalent `docker run` command |
