# DAST Scan Automation for OpenShift Operators

Generic, config-driven framework for DAST (Dynamic Application Security Testing) scanning of OpenShift operators. Supports two scan types:

| Scan Type | Tool | What it tests |
|-----------|------|---------------|
| **OOBTKUBE** | `scripts/automate_dast_scan.py` | Command injection via CR reconciliation |
| **ZAP** | `scripts/automate_zap_scan.py` | HTTP/API security of Kubernetes API groups |
| **Both + GCS** | `run_all_dast_scans.py` | Main entry point: runs both, uploads combined tarball to GCS |

Works with any operator—ZTWIM, Service Mesh, or custom operators—by providing an operator-specific config file.

---

## Project Structure

```
dast-scan-automation/
├── run_all_dast_scans.py     # Main entry point (runs both scans + GCS upload)
├── dast/                     # Shared framework (config, oc, utils, oobtkube, zap)
│   ├── config.py             # YAML loading, GCS config helpers
│   ├── oc.py                 # OpenShift/oc CLI helpers (prerequisites, API URL/token)
│   ├── utils.py              # run_cmd, get_timestamp_dir, get_script_dir
│   ├── oobtkube.py           # OOBTKUBE scan logic (export CRs, run scans)
│   └── zap.py                # ZAP scan logic (update configs, run RapiDAST)
├── scripts/                  # Helper scripts (invoked by run_all_dast_scans.py)
│   ├── automate_dast_scan.py # OOBTKUBE scan
│   ├── automate_zap_scan.py   # ZAP scan
│   └── update-zap-config.sh   # Manual ZAP config helper
├── config/
│   ├── oobtkube/             # OOBTKUBE operator configs
│   └── zap/                  # ZAP operator + RapiDAST configs
├── exports/                  # GCS upload scripts
└── oobtkube-op/ zap-op/      # Scan results (per operator, timestamped)
```

---

## Quick Start: run_all_dast_scans.py

The main entry point runs **both OOBTKUBE and ZAP scans**, then uploads a combined tarball to GCS.

### Prerequisites for run_all_dast_scans.py

| Requirement | Details |
|-------------|---------|
| **OpenShift cluster** | `oc` CLI configured, operator installed (e.g. ZTWIM in `zero-trust-workload-identity-manager`) |
| **Podman or Docker** | For ZAP scans (RapiDAST runs in a container) |
| **Python 3.x + PyYAML** | `pip install -r requirements.txt` |
| **Callback IP** | IP reachable from cluster pods; auto-detect or use `--callback-ip` |
| **Firewall** | Port 12345 open: `sudo firewall-cmd --add-port=12345/tcp` |
| **GCS (optional)** | For upload: `config.oobtkube.ztwim.yaml` with `googleCloudStorage` and service account key |

### Run

```bash
cd dast-scan-automation
pip install -r requirements.txt

# Run for ZTWIM (OOBTKUBE + ZAP)
python3 run_all_dast_scans.py --operator ztwim

# Run for ESO (OOBTKUBE only; ZAP skipped if config/zap/eso.yaml does not exist)
python3 run_all_dast_scans.py --operator eso

# First time: download RapiDAST
python3 run_all_dast_scans.py --operator ztwim --download-rapidast

# Override callback IP if auto-detect fails
python3 run_all_dast_scans.py --operator ztwim --callback-ip <YOUR_IP>

# Custom config paths (alternative to --operator)
python3 run_all_dast_scans.py --config config/oobtkube/ztwim.yaml --zap-config config/zap/ztwim.yaml

# Skip GCS upload
python3 run_all_dast_scans.py --operator ztwim --skip-upload
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `--operator`, `-o` | **Yes*** | Operator name (ztwim, eso, etc.). Uses `config/oobtkube/<operator>.yaml` and `config/zap/<operator>.yaml` |
| `--config`, `-c` | **Yes*** | OOBTKUBE config path. Alternative to `--operator` |
| `--zap-config` | No | ZAP config path. If omitted, uses `config/zap/<operator>.yaml`. ZAP is skipped if file does not exist |
| `--callback-ip` | No | IP reachable from cluster pods. Auto-detect if not set |
| `--skip-upload` | No | Skip GCS upload |
| `--download-rapidast` | No | Clone RapiDAST if missing (first run) |

\* Either `--operator` or `--config` required.

### Output

- **oobtkube-op/ztwim/&lt;timestamp&gt;/** — OOBTKUBE SARIF
- **zap-op/ztwim/&lt;timestamp&gt;/** — ZAP SARIF (operator + operands)
- **GCS:** `gs://{bucket}/operators/ztwim/{timestamp}-RapiDAST-ZTWIM-DAST-{random}.tgz`

### Cleaning up results (SELinux / Fedora)

ZAP uses Podman with `:Z` mounts; files may get `container_file_t` context. To remove:

```bash
sudo restorecon -Rv zap-op/ oobtkube-op/
rm -rf zap-op/ oobtkube-op/
```

---

## Prerequisites (detailed)

### 1. OpenShift Cluster

- OpenShift cluster with `oc` CLI configured
- **Operator installed** in a namespace (e.g. `zero-trust-workload-identity-manager` for ZTWIM)
- Verify with: `oc get pods -n <your-namespace>`

### 2. RapiDAST

**Option A: Clone manually**
```bash
cd dast-scan-automation
git clone https://github.com/RedHatProductSecurity/rapidast.git
```

**Option B: Let the script download (recommended)**
```bash
python3 scripts/automate_dast_scan.py --download-rapidast
# or: python3 run_all_dast_scans.py --operator ztwim --download-rapidast
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

### 6. GCS (for upload)

Configure in `config/oobtkube/ztwim.yaml`:

```yaml
config:
  googleCloudStorage:
    keyFile: "rapidast-sa-operators-ztwim_key.json"
    bucketName: "your-bucket"
    directory: "operators/ztwim"
```

---

## Usage

### Run Both Scans and Upload Combined to GCS

```bash
python3 run_all_dast_scans.py --operator ztwim --callback-ip <YOUR_IP>
```

Runs OOBTKUBE and ZAP, then uploads a single tarball to GCS containing all results (oobtkube-op, ZAP operator, ZAP operands) at `gs://{bucket}/operators/ztwim/{timestamp}-RapiDAST-ZTWIM-DAST-{random}.tgz`.

### Basic Run (default config: ZTWIM)

```bash
cd dast-scan-automation
python3 scripts/automate_dast_scan.py
```

### First-time Run (download RapiDAST + scan)

```bash
cd dast-scan-automation
pip install -r requirements.txt
python3 scripts/automate_dast_scan.py --download-rapidast
```

### Specify Config File

```bash
python3 scripts/automate_dast_scan.py --config config/oobtkube/ztwim.yaml
```

### Specify Callback IP

```bash
python3 scripts/automate_dast_scan.py --callback-ip 10.215.98.167
```

### Full Example

```bash
python3 scripts/automate_dast_scan.py \
  --config config/oobtkube/ztwim.yaml \
  --callback-ip 10.215.98.167 \
  --download-rapidast \
  --namespace zero-trust-workload-identity-manager \
  --duration 120 \
  --port 12345
```

---

## Using for Other Operators

The framework is generic. To scan a **different operator**, create a config file and run with `--config`.

### Step 1: Find Your Operator's CRs

List Custom Resources in your operator's namespace:

```bash
# List all API resources (find the plural name)
oc api-resources | grep -i <your-operator>

# List CR instances in your namespace
oc get <plural> -n <namespace>
```

Example for a hypothetical "MyOperator":
```bash
oc api-resources | grep -i myoperator
# myoperatorconfigs   moc   v1   MyOperatorConfig

oc get myoperatorconfigs -n openshift-myoperator
# NAME      AGE
# cluster   5d
```

### Step 2: Create a Config File

Copy the example template and customize:

```bash
cp config/oobtkube/example-operator.yaml config/oobtkube/my-operator.yaml
```

Edit `config/oobtkube/my-operator.yaml`:

```yaml
operator: my-operator
namespace: openshift-myoperator
cr_configs:
  - resource: myoperatorconfigs    # Kubernetes resource type (oc get <resource>)
    instance: cluster              # Name of this CR instance
  # Add more CRs as needed:
  # - resource: myoperatorinstances
  #   instance: default

application:
  shortName: "MY-OPERATOR-DAST"

# Optional: GCS export
config:
  googleCloudStorage:
    keyFile: ""
    bucketName: ""
    directory: ""
```

**Config keys:** Use `resource`/`instance` (recommended) or `plural`/`name`—both work.

### Step 3: Run the Scan

```bash
python3 scripts/automate_dast_scan.py --config config/oobtkube/my-operator.yaml
```

### Step 4: View Results

Results are stored per operator:

```
oobtkube-op/
├── ztwim/                          # ZTWIM operator runs
│   └── 2026-03-02_10-30-00/
│       └── oobtkube-*-results.sarif
└── my-operator/                    # Your operator runs
    └── 2026-03-02_11-00-00/
        └── oobtkube-*-results.sarif
```

---

## ZAP API Scanning (Optional)

ZAP scans the Kubernetes API for HTTP-level issues. Results stored in `zap-op/<operator>/<timestamp>/` (like oobtkube-op).

**Automated (recommended):**

```bash
python3 scripts/automate_zap_scan.py --config config/zap/ztwim.yaml
```

Runs both operator and operands scans, stores SARIF in `zap-op/ztwim/<timestamp>/zap-operator-results.sarif` and `zap-operands-results.sarif`, and uploads to GCP if configured.

**Manual (step-by-step):**

```bash
./scripts/update-zap-config.sh
mkdir -p zap-op && chmod o+w zap-op
podman run -v $(pwd)/config/zap/ztwim-operator.yaml:/opt/rapidast/config/config.yaml:Z \
  -v $(pwd)/zap-op/:/opt/rapidast/results/:Z \
  quay.io/redhatproductsecurity/rapidast:latest
podman run -v $(pwd)/config/zap/ztwim-operands.yaml:/opt/rapidast/config/config.yaml:Z \
  -v $(pwd)/zap-op/:/opt/rapidast/results/:Z \
  quay.io/redhatproductsecurity/rapidast:latest
```

**Upload ZAP results to GCP:**

```bash
python3 exports/upload_zap_results.py --config config/zap/ztwim.yaml
python3 exports/upload_zap_results.py --config config/zap/ztwim.yaml --all
```

Uploads the latest `zap-op/ztwim/<timestamp>/` (or all with `--all`) as a gzipped tarball to GCS.

See [docs/ZTWIM-DAST-Guide.md](docs/ZTWIM-DAST-Guide.md) for the full guide.

---

## Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--config`, `-c` | config/oobtkube/ztwim.yaml | Path to operator config YAML |
| `--namespace` | from config | Operator namespace (overrides config) |
| `--callback-ip` | auto-detect | IP reachable from cluster pods |
| `--duration` | 120 | Scan duration per CR (seconds) |
| `--port` | 12345 | Callback listener port |
| `--download-rapidast` | false | Clone RapiDAST from GitHub if not present |
| `--skip-export` | false | Skip CR export; use existing Cr-Configs/ |

---

## Config File Structure

```yaml
# Framework (optional; defaults are used if omitted)
framework:
  rapidastRepo: "https://github.com/RedHatProductSecurity/rapidast.git"
  rapidastDir: "rapidast"
  configDir: "Cr-Configs"
  resultBaseDir: "oobtkube-op"
  oobtkubeScript: "scanners/generic/tools/oobtkube.py"

# Operator (required)
operator: ztwim
namespace: zero-trust-workload-identity-manager
cr_configs:
  - resource: zerotrustworkloadidentitymanagers
    instance: cluster
  # or: plural / name (both supported)

# Application metadata (for GCS export)
application:
  shortName: "ZTWIM-DAST"

# GCS export (optional)
config:
  googleCloudStorage:
    keyFile: "rapidast-sa-operators-ztwim_key.json"
    bucketName: "secaut-bucket"
    directory: "operators/ztwim"
```

---

## Output Structure

Each run creates a **timestamped directory** under `oobtkube-op/<operator>/`. CR configs are stored **per operator** in `Cr-Configs/<operator>/` so multiple operators can be scanned without mixing files:

```
dast-scan-automation/
├── run_all_dast_scans.py     # Main entry point: run both + upload combined to GCS
├── scripts/
│   ├── automate_dast_scan.py # OOBTKUBE scan automation
│   └── automate_zap_scan.py  # ZAP scan automation
├── config/
│   ├── zap/                  # ZAP (RapiDAST) scan configs
│   │   ├── ztwim.yaml            # ZAP orchestration config
│   │   ├── ztwim-operator.yaml   # Operator CRs
│   │   └── ztwim-operands.yaml   # Operands CRs
│   └── oobtkube/             # OOBTKUBE operator configs
│       ├── ztwim.yaml        # ZTWIM operator
│       ├── eso.yaml          # External Secrets Operator
│       └── example-operator.yaml  # Template for new operators
├── exports/
│   ├── gcs_export.py          # GCS upload logic
│   └── upload_zap_results.py  # ZAP results upload
├── rapidast/                 # Cloned by --download-rapidast
├── Cr-Configs/               # Per-operator CR YAML files
│   ├── ztwim/
│   │   ├── zerotrustworkloadidentitymanagers-cr-oobtkube.yaml
│   │   └── ...
│   ├── eso/
│   │   ├── externalsecrets-cr-oobtkube.yaml
│   │   └── secretstores-cr-oobtkube.yaml
│   └── my-operator/
│       └── ...
├── oobtkube-op/              # OOBTKUBE scan results
│   ├── ztwim/
│   │   └── 2026-03-02_10-30-00/
│   │       └── oobtkube-*-results.sarif
│   └── eso/
│       └── 2026-03-02_11-00-00/
│           └── oobtkube-*-results.sarif
└── zap-op/                   # ZAP scan results (like oobtkube-op)
    └── ztwim/
        └── 2026-03-19_10-30-00/
            ├── zap-operator-results.sarif
            └── zap-operands-results.sarif
```

---

## What the Script Does

1. **Loads config** — Reads operator settings (namespace, CRs) from YAML
2. **Ensures RapiDAST** — Clones from GitHub only if not present
3. **Checks prerequisites** — oc CLI, cluster access, namespace, pods
4. **Migrate (one-time)** — Moves CR files from flat `Cr-Configs/` to `Cr-Configs/<operator>/` if present
5. **Restore CRs** — Restores CRs from `Cr-Configs/<operator>/` so cluster starts clean
6. **Exports CRs** — Exports configured CRs to `Cr-Configs/<operator>/`
7. **Runs OOBTKUBE** — Scans each CR in the operator's config dir for command injection
8. **Stores results** — Saves SARIF files in `oobtkube-op/<operator>/<timestamp>/`
9. **GCS export** — Optionally uploads results if configured

---

## View Results

```bash
# View a specific run
cat oobtkube-op/ztwim/2026-03-02_10-30-00/oobtkube-*-results.sarif | jq .

# List all runs for an operator
ls -la oobtkube-op/ztwim/
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Specify operator/config | run_all_dast_scans.py requires `--operator <name>` or `--config <path>` |
| Config file not found | Use `--operator` or `--config` with correct path |
| namespace/cr_configs required | Ensure config file has `namespace` and `cr_configs` |
| RapiDAST not found | Run with `--download-rapidast` |
| Callback IP not detected | Use `--callback-ip YOUR_IP` (auto-detect may fail on some networks) |
| No callback received | Verify firewall allows port; ensure cluster can reach your IP |
| Namespace not found | Check operator is installed; set `namespace` in config or `--namespace` |
| PyYAML missing | `pip install -r requirements.txt` |
| Cannot remove zap-op/ oobtkube-op/ | SELinux: `sudo restorecon -Rv zap-op/ oobtkube-op/` then `rm -rf` |
| Podman/Docker not found | ZAP requires Podman or Docker; install and ensure in PATH |
| ZAP Operator scan timeout, no SARIF | Operator scan (61+ URLs) can take 60-90 min. Set `zap.timeoutMinutes: 90` (or higher) in `config/zap/ztwim.yaml` |

---

## Rerunning

The script can be **rerun repeatedly** without manual cleanup:

- **Restore precheck** — Before each run, CRs are restored from `Cr-Configs/<operator>/`
- **RapiDAST** — Never re-cloned if already present
- **Results** — Each run creates a new timestamped directory; previous results are kept
- **Multi-operator** — Each operator uses its own config dir; ZTWIM and ESO scans do not interfere

---

## Example: ZTWIM Operator (Default Config)

The default `config/oobtkube/ztwim.yaml` is configured for ZTWIM:

- **Operator:** ZeroTrustWorkloadIdentityManager
- **Operands:** SpireServer, SpireAgent, SpiffeCSIDriver, SpireOIDCDiscoveryProvider
- **Namespace:** zero-trust-workload-identity-manager
