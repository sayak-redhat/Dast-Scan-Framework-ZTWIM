# DAST Scan Automation for OpenShift Operators

Generic, config-driven framework for DAST (Dynamic Application Security Testing) scanning of OpenShift operators using RapiDAST OOBTKUBE. Works with any operator—ZTWIM, Service Mesh, or custom operators—by providing an operator-specific config file.

---

## Prerequisites

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

### Basic Run (default config: ZTWIM)

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

### Specify Config File

```bash
python3 automate_dast_scan.py --config config/ztwim.yaml
```

### Specify Callback IP

```bash
python3 automate_dast_scan.py --callback-ip 10.215.98.167
```

### Full Example

```bash
python3 automate_dast_scan.py \
  --config config/ztwim.yaml \
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
cp config/example-operator.yaml config/my-operator.yaml
```

Edit `config/my-operator.yaml`:

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
python3 automate_dast_scan.py --config config/my-operator.yaml
```

### Step 4: View Results

Results are stored per operator:

```
Dastscan-op/
├── ztwim/                          # ZTWIM operator runs
│   └── 2026-03-02_10-30-00/
│       └── oobtkube-*-results.sarif
└── my-operator/                    # Your operator runs
    └── 2026-03-02_11-00-00/
        └── oobtkube-*-results.sarif
```

---

## Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--config`, `-c` | config/ztwim.yaml | Path to operator config YAML |
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
  resultBaseDir: "Dastscan-op"
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

Each run creates a **timestamped directory** under `Dastscan-op/<operator>/`. CR configs are stored **per operator** in `Cr-Configs/<operator>/` so multiple operators can be scanned without mixing files:

```
dast-scan-automation/
├── automate_dast_scan.py
├── config/
│   ├── ztwim.yaml            # ZTWIM operator
│   ├── eso.yaml              # External Secrets Operator
│   └── example-operator.yaml  # Template for new operators
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
└── Dastscan-op/
    ├── ztwim/
    │   └── 2026-03-02_10-30-00/
    │       └── oobtkube-*-results.sarif
    └── eso/
        └── 2026-03-02_11-00-00/
            └── oobtkube-*-results.sarif
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
8. **Stores results** — Saves SARIF files in `Dastscan-op/<operator>/<timestamp>/`
9. **GCS export** — Optionally uploads results if configured

---

## View Results

```bash
# View a specific run
cat Dastscan-op/ztwim/2026-03-02_10-30-00/oobtkube-*-results.sarif | jq .

# List all runs for an operator
ls -la Dastscan-op/ztwim/
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Config file not found | Use `--config` with correct path; default is `config/ztwim.yaml` |
| namespace/cr_configs required | Ensure config file has `namespace` and `cr_configs` |
| RapiDAST not found | Run with `--download-rapidast` |
| Callback IP not detected | Use `--callback-ip YOUR_IP` |
| No callback received | Verify firewall allows port; ensure cluster can reach your IP |
| Namespace not found | Check operator is installed; set `namespace` in config or `--namespace` |
| PyYAML missing | `pip install -r requirements.txt` |

---

## Rerunning

The script can be **rerun repeatedly** without manual cleanup:

- **Restore precheck** — Before each run, CRs are restored from `Cr-Configs/<operator>/`
- **RapiDAST** — Never re-cloned if already present
- **Results** — Each run creates a new timestamped directory; previous results are kept
- **Multi-operator** — Each operator uses its own config dir; ZTWIM and ESO scans do not interfere

---

## Example: ZTWIM Operator (Default Config)

The default `config/ztwim.yaml` is configured for ZTWIM:

- **Operator:** ZeroTrustWorkloadIdentityManager
- **Operands:** SpireServer, SpireAgent, SpiffeCSIDriver, SpireOIDCDiscoveryProvider
- **Namespace:** zero-trust-workload-identity-manager
