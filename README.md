# DAST Scan Automation for ZTWIM Operator

Automated DAST (Dynamic Application Security Testing) scanning for the Zero Trust Workload Identity Manager operator on OpenShift using RapiDAST OOBTKUBE.

---

## Prerequisites

### 1. OpenShift Cluster

- OpenShift cluster with `oc` CLI configured
- **ZTWIM operator and operands installed** in `zero-trust-workload-identity-manager` namespace
- Verify with: `oc get pods -n zero-trust-workload-identity-manager`

### 2. RapiDAST

**Option A: Clone manually**
```bash
cd dast-scan-automation
git clone https://github.com/RedHatProductSecurity/rapidast.git
```

**Option B: Let the script download (recommended)**
```bash
python3 automate_dast_scan.py --download-rapidast
```
RapiDAST is cloned only when missing. If the repo already exists, it is **never re-downloaded**.

### 3. Python Dependencies

```bash
pip install -r requirements.txt
```

### 4. Network

- **Callback IP** must be reachable from cluster pods
- **Firewall**: Open port 12345 (or your chosen port)
  ```bash
  sudo firewall-cmd --add-port=12345/tcp
  ```

### 5. Kubeconfig

```bash
export KUBECONFIG=/path/to/your/kubeconfig
```

---

## Usage

### Basic Run (auto-detect callback IP, requires rapidast cloned)

```bash
cd dast-scan-automation
python3 automate_dast_scan.py
```

### First-time Run (download RapiDAST + scan)

```bash
cd dast-scan-automation
pip install -r requirements.txt
python3 automate_dast_scan.py --download-rapidast
```

### Specify Callback IP

```bash
python3 automate_dast_scan.py --callback-ip 10.215.98.167
```

### Full Example

```bash
python3 automate_dast_scan.py \
  --callback-ip 10.215.98.167 \
  --download-rapidast \
  --namespace zero-trust-workload-identity-manager \
  --duration 120 \
  --port 12345
```

---

## Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--namespace` | zero-trust-workload-identity-manager | Operator namespace |
| `--callback-ip` | auto-detect | IP reachable from cluster pods |
| `--duration` | 120 | Scan duration per CR (seconds) |
| `--port` | 12345 | Callback listener port |
| `--download-rapidast` | false | Clone RapiDAST from GitHub if not present |
| `--skip-export` | false | Skip CR export; use existing Cr-Configs/ |

---

## Output Structure

Each run creates a **timestamped directory** under `Dastscan-op/`:

```
dast-scan-automation/
├── automate_dast_scan.py
├── requirements.txt
├── README.md
├── rapidast/                    # Cloned by --download-rapidast
├── Cr-Configs/                  # Exported CR YAML files
│   ├── zerotrustworkloadidentitymanagers-cr-oobtkube.yaml
│   ├── spireservers-cr-oobtkube.yaml
│   ├── spireagents-cr-oobtkube.yaml
│   ├── spiffecsidrivers-cr-oobtkube.yaml
│   └── spireoidcdiscoveryproviders-cr-oobtkube.yaml
└── Dastscan-op/
    ├── 2026-02-26_14-30-00/     # Timestamped run
    │   ├── oobtkube-zerotrustworkloadidentitymanagers-cr-oobtkube-results.sarif
    │   ├── oobtkube-spireservers-cr-oobtkube-results.sarif
    │   ├── oobtkube-spireagents-cr-oobtkube-results.sarif
    │   ├── oobtkube-spiffecsidrivers-cr-oobtkube-results.sarif
    │   └── oobtkube-spireoidcdiscoveryproviders-cr-oobtkube-results.sarif
    └── 2026-02-26_16-45-00/     # Another run
        └── ...
```

---

## What the Script Does

1. **Ensures RapiDAST** — Clones from GitHub only if not present (never re-downloads if repo exists)
2. **Checks prerequisites** — oc CLI, cluster access, namespace, pods
3. **Precheck: Restore CRs** — Restores CRs from Cr-Configs/ (from previous run) so cluster starts clean
4. **Exports CRs** — Exports all 5 CRs (operator + operands) to Cr-Configs/
5. **Runs OOBTKUBE** — Scans each CR for command injection
6. **Stores results** — Saves SARIF files in `Dastscan-op/YYYY-MM-DD_HH-MM-SS/`

---

## View Results

```bash
# View a specific run
cat Dastscan-op/2026-02-26_14-30-00/oobtkube-*-results.sarif | jq .

# List all runs
ls -la Dastscan-op/
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| RapiDAST not found | Run with `--download-rapidast` |
| Callback IP not detected | Use `--callback-ip YOUR_IP` |
| No callback received | Verify firewall allows port; ensure cluster can reach your IP |
| Namespace not found | Check operator is installed; use `--namespace` if different |
| PyYAML missing | `pip install -r requirements.txt` |

---

## Rerunning

The script can be **rerun repeatedly** without manual cleanup:

- **Restore precheck** — Before each run, CRs are restored from Cr-Configs/ (from the previous run), so the cluster starts clean
- **RapiDAST** — Never re-cloned if already present
- **Results** — Each run creates a new timestamped directory; previous results are kept

---

## CRs Scanned

- **Operator:** ZeroTrustWorkloadIdentityManager
- **Operands:** SpireServer, SpireAgent, SpiffeCSIDriver, SpireOIDCDiscoveryProvider
