# DAST Scan Automation for OpenShift Operators

Generic, config-driven framework for DAST (Dynamic Application Security Testing) scanning of OpenShift operators. Supports OOBTKUBE, ZAP, and optional Trivy k8s misconfiguration (RapiDAST `generic_trivy`).

| Scan Type | Tool | What it tests |
|-----------|------|---------------|
| **OOBTKUBE** | `scripts/automate_oobtkube_scan.py` | Command injection via CR reconciliation |
| **ZAP** | `scripts/automate_zap_scan.py` | HTTP/API security of Kubernetes API groups |
| **Trivy k8s** | `scripts/automate_trivy_scan.py` | Cluster misconfiguration (`trivy k8s`, SARIF via RapiDAST) |
| **Combined + GCS** | `run_all_dast_scans.py` | OOBTKUBE + ZAP + Trivy (if `trivy/trivy.yaml` exists), combined tarball to GCS |

Works with any operator—ZTWIM, Service Mesh, or custom operators—by providing an operator-specific config file.

ZAP policy choices, 403 triage, and Trivy notes: [docs/ZAP-RBAC-and-Review-Notes.md](docs/ZAP-RBAC-and-Review-Notes.md).

---

## Project Structure

```
dast-scan-automation/
├── run_all_dast_scans.py     # Main entry point (runs both scans + GCS upload)
├── dast/                     # Shared framework (config, oc, utils, oobtkube, zap, trivy)
│   ├── config.py             # YAML loading, GCS config helpers
│   ├── oc.py                 # OpenShift/oc CLI helpers (prerequisites, API URL/token)
│   ├── utils.py              # run_cmd, get_timestamp_dir, get_script_dir
│   ├── oobtkube.py           # OOBTKUBE scan logic (export CRs, run scans)
│   ├── zap.py                # ZAP scan logic (render runtime configs, run RapiDAST)
│   └── trivy.py              # Trivy k8s via RapiDAST (kubeconfig mount)
├── scripts/                  # Helper scripts (invoked by run_all_dast_scans.py)
│   ├── automate_oobtkube_scan.py # OOBTKUBE scan
│   ├── automate_zap_scan.py   # ZAP scan
│   ├── automate_trivy_scan.py # Trivy k8s (RapiDAST generic_trivy)
│   ├── clean-artifacts.sh     # Remove results, caches, stale keys (safe before commits)
│   └── update-zap-config.sh   # DEPRECATED — automation handles token injection now
├── config/
│   └── operators/            # Per-operator: oobtkube.yaml + zap/ + optional trivy/
│       └── ztwim/            # ZTWIM example
│           ├── oobtkube.yaml
│           ├── zap/
│           │   ├── zap.yaml             # ZAP orchestration (image, timeout, GCS)
│           │   ├── zap-operator.yaml    # Operator API scan config
│           │   ├── zap-operands.yaml    # Operands API scan config
│           │   └── dast-zap-setup.yaml  # SA/RBAC bootstrap (oc apply)
│           └── trivy/
│               ├── trivy.yaml           # Trivy orchestration
│               └── trivy-k8s.yaml       # RapiDAST generic_trivy config
├── exports/                  # GCS upload scripts
└── results/                  # Scan output (gitignored)
    ├── oobtkube/<operator>/<timestamp>/
    ├── zap/
    │   ├── flat/<operator>/<timestamp>/   # flat SARIF + HTML copies
    │   └── rapidast/<ZTWIM-*-ZAP>/        # RapiDAST DAST-* trees
    └── trivy/
        ├── flat/<operator>/<timestamp>/   # flat Trivy SARIF
        └── rapidast/<ZTWIM-Trivy-K8s>/     # RapiDAST DAST-* trees
```

Operator YAML layout (OOBTKUBE at the root, ZAP under `zap/`) is documented in [config/operators/README.md](config/operators/README.md).

---

## Quick Start: run_all_dast_scans.py

The main entry point runs **OOBTKUBE and ZAP**, and **Trivy k8s** when [`config/operators/<operator>/trivy/trivy.yaml`](config/operators/ztwim/trivy/trivy.yaml) exists, then uploads a combined tarball to GCS (unless `--skip-upload`). Use **`--skip-trivy`** to skip Trivy only.

### Steps to run (new cluster or first time)

1. **Clone / enter the repo and install Python dependencies**
   ```bash
   cd dast-scan-automation
   pip install -r requirements.txt
   ```

2. **Point `oc` at your cluster**
   ```bash
   export KUBECONFIG=/path/to/your/kubeconfig
   oc whoami
   oc get pods -n zero-trust-workload-identity-manager   # ZTWIM example
   ```

3. **RapiDAST (required for OOBTKUBE)** — clone once or let the script do it:
   ```bash
   python3 run_all_dast_scans.py --operator ztwim --download-rapidast --skip-upload
   ```
   Or clone manually: `git clone https://github.com/RedHatProductSecurity/rapidast.git` in the repo root.

4. **ZAP token (strongly recommended)** — the default in-cluster token often gets **403** on API paths. Prefer a user OAuth token or a dedicated service account (see [docs/ZAP-RBAC-and-Review-Notes.md](docs/ZAP-RBAC-and-Review-Notes.md)):
   ```bash
   # Works when your kubeconfig session has a bearer token (not cert-only):
   export ZAP_KUBERNETES_TOKEN="$(oc whoami -t)"
   ```
   If `oc whoami -t` errors with **no token is currently in use**, your login is **cert-only** (typical for some cluster-bot kubeconfigs). Skip the export and use **`ZAP_SERVICE_ACCOUNT` + `ZAP_TOKEN_NAMESPACE`** with an SA that has API read access (see the doc), or use `oc login` in a way that stores a token.

5. **Callback IP (OOBTKUBE)** — must be reachable **from cluster pods** on port **12345** (default). **If you do not pass `--callback-ip`, the script auto-detects** a local IP (`hostname -I` / routing). Add `--callback-ip <YOUR_IP>` only when auto-detect picks the wrong interface (VPN, multiple NICs, etc.). Open the firewall: `sudo firewall-cmd --add-port=12345/tcp`

6. **GCS (optional)** — place the service account JSON in the `secrets/` directory (gitignored). Configs reference it as `keyFile: "secrets/<name>_key.json"`. Skip upload while testing: `--skip-upload`.

7. **Run the full pipeline (ZTWIM example)**
   ```bash
   # Optional if oc whoami -t works:
   # export ZAP_KUBERNETES_TOKEN="$(oc whoami -t)"
   # Auto-detect callback IP (omit --callback-ip)
   python3 run_all_dast_scans.py --operator ztwim
   # Or set explicitly when auto-detect is wrong:
   # python3 run_all_dast_scans.py --operator ztwim --callback-ip <YOUR_LAN_IP>
   ```
   **Test without GCS:** add `--skip-upload`.  
   **OOBTKUBE verbosity:** default is **debug** (verbose run logs). Use `--oobtkube-log-level info` for quieter logs.  
   **ESO only (no ZAP unless `config/operators/eso/zap/zap.yaml` exists):** `--operator eso`.

### Prerequisites (summary)

| Requirement | Details |
|-------------|---------|
| **OpenShift cluster** | `oc` configured; operator installed in the namespace from config |
| **Podman or Docker** | For ZAP (RapiDAST container) |
| **Python 3 + PyYAML** | `pip install -r requirements.txt` |
| **Callback IP** | Omitted ⇒ auto-detect; pass `--callback-ip` if pods cannot reach that IP |
| **Firewall** | Port 12345 (or `--port` on OOBTKUBE script): `sudo firewall-cmd --add-port=12345/tcp` |
| **ZAP API access** | `ZAP_KUBERNETES_TOKEN` if `oc whoami -t` works; else SA + `ZAP_SERVICE_ACCOUNT` / `ZAP_TOKEN_NAMESPACE` (see [ZAP RBAC notes](docs/ZAP-RBAC-and-Review-Notes.md)) |
| **GCS (optional)** | Key file in `secrets/` + `bucketName` in config; use `--skip-upload` to disable |

### Environment variables (ZAP)

| Variable | Purpose |
|----------|---------|
| `ZAP_KUBERNETES_TOKEN` | Bearer token (`$(oc whoami -t)` if your session has one; cert-only kubeconfigs need SA tokens instead) |
| `RAPIDAST_TOKEN` | Same as above (alias) |
| `ZAP_SERVICE_ACCOUNT` / `ZAP_TOKEN_NAMESPACE` | Use `oc create token <sa> -n <ns>` instead of default |
| `ZAP_API_SERVER` | Override API URL (optional) |

### Common commands

```bash
cd dast-scan-automation
pip install -r requirements.txt
export KUBECONFIG=/path/to/kubeconfig
# export ZAP_KUBERNETES_TOKEN="$(oc whoami -t)"   # skip if cert-only kubeconfig; use SA vars per docs

# Full run: OOBTKUBE + ZAP + combined GCS upload (callback IP auto-detected)
python3 run_all_dast_scans.py --operator ztwim

# Override callback IP if auto-detect is wrong
python3 run_all_dast_scans.py --operator ztwim --callback-ip <YOUR_IP>

# No GCS (local testing)
python3 run_all_dast_scans.py --operator ztwim --skip-upload

# First time without manual RapiDAST clone
python3 run_all_dast_scans.py --operator ztwim --download-rapidast --skip-upload

# Quieter OOBTKUBE logs (default is debug / verbose)
python3 run_all_dast_scans.py --operator ztwim --oobtkube-log-level info

# ESO: OOBTKUBE only if config/operators/eso/zap/zap.yaml is missing
python3 run_all_dast_scans.py --operator eso

# Explicit ZAP config path
python3 run_all_dast_scans.py --operator ztwim --zap-config config/operators/ztwim/zap/zap.yaml

# ZAP: mount templates as-is (skip token injection — you must fill placeholders manually)
python3 run_all_dast_scans.py --operator ztwim --skip-zap-config-update
```

### Arguments (`run_all_dast_scans.py`)

| Argument | Required | Description |
|----------|----------|-------------|
| `--operator`, `-o` | **Yes*** | Operator name (ztwim, eso). Uses `config/operators/<operator>/oobtkube.yaml` and `config/operators/<operator>/zap/zap.yaml` |
| `--config`, `-c` | **Yes*** | OOBTKUBE config path (alternative to `--operator`) |
| `--zap-config` | No | ZAP orchestration YAML. Default: `config/operators/<operator>/zap/zap.yaml`. ZAP skipped if missing |
| `--callback-ip` | No | IP reachable from cluster pods. **If omitted, auto-detect** (pass only when the wrong IP is chosen) |
| `--skip-upload` | No | Skip GCS (sub-scripts also skip per-scan upload; combined upload at end skipped) |
| `--download-rapidast` | No | Clone RapiDAST if missing |
| `--oobtkube-log-level` | No | Overrides config. Default in YAML is **`debug`** (verbose); omit flag to use config |
| `--skip-zap-config-update` | No | Do not inject API URL/token from `oc`; use **`Bearer ...`** and URLs already set in `config/operators/<op>/zap/zap-operator.yaml` / `zap/zap-operands.yaml` |
| `--skip-zap-bootstrap` | No | Skip `oc apply` of `dast-zap-setup.yaml` (SA/RBAC). Useful when SA already exists or you lack cluster-admin |
| `--skip-trivy` | No | Skip Trivy k8s scan even if `config/operators/<operator>/trivy/trivy.yaml` exists |

\* Either `--operator` or `--config` required.

### Output

- **results/oobtkube/&lt;operator&gt;/&lt;timestamp&gt;/** — OOBTKUBE SARIF (`oobtkube-*-results.sarif`) and **run logs** (`oobtkube-*-run.log`, stdout/stderr from RapiDAST oobtkube)
- **results/zap/flat/&lt;operator&gt;/&lt;timestamp&gt;/** — flat ZAP SARIF + HTML copies; full RapiDAST output under **results/zap/rapidast/&lt;ZTWIM-*-ZAP&gt;/DAST-***
- **results/trivy/flat/&lt;operator&gt;/&lt;timestamp&gt;/** — flat Trivy SARIF; full RapiDAST output under **results/trivy/rapidast/&lt;shortName&gt;/DAST-***
- **GCS:** `gs://{bucket}/{directory}/{timestamp}-RapiDAST-{app}-*.tgz` (combined tarball when upload enabled)

### Cleaning up results (SELinux / Fedora)

**Preferred:** use the cleanup script, which handles `results/`, `oobtkube-config/`, `rapidast/`, `__pycache__`, stale key files, and Podman-owned directories (`zap-op/`) with an automatic `podman unshare` fallback:

```bash
scripts/clean-artifacts.sh
```

**Manual:** ZAP uses Podman with `:Z` mounts; files may get `container_file_t` context. To remove:

```bash
sudo restorecon -Rv results/
rm -rf results/
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
python3 scripts/automate_oobtkube_scan.py --download-rapidast
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

Place the service account key in the `secrets/` directory (gitignored), then reference it in `config/operators/ztwim/oobtkube.yaml`:

```yaml
config:
  googleCloudStorage:
    keyFile: "secrets/rapidast-sa-operators-ztwim_key.json"
    bucketName: "your-bucket"
    directory: "operators/ztwim"
```

---

## Usage

The **recommended** path is [`run_all_dast_scans.py`](#quick-start-run_all_dast_scanspy) (numbered steps, token, callback, flags). The snippets below cover **OOBTKUBE-only** (`automate_oobtkube_scan.py`) and overrides.

### Run Both Scans and Upload Combined to GCS

```bash
python3 run_all_dast_scans.py --operator ztwim
# Optional: --callback-ip <YOUR_IP>  (omit to auto-detect)
```

Runs OOBTKUBE, ZAP, and Trivy (if `trivy/trivy.yaml` exists), then uploads a single tarball to GCS containing those results (`results/oobtkube`, `results/zap/rapidast`, `results/trivy/rapidast`, etc.) at `gs://{bucket}/operators/ztwim/{timestamp}-RapiDAST-ZTWIM-DAST-{random}.tgz`.

### Basic Run (default config: ZTWIM)

```bash
cd dast-scan-automation
python3 scripts/automate_oobtkube_scan.py
```

### First-time Run (download RapiDAST + scan)

```bash
cd dast-scan-automation
pip install -r requirements.txt
python3 scripts/automate_oobtkube_scan.py --download-rapidast
```

### Specify Config File

```bash
python3 scripts/automate_oobtkube_scan.py --config config/operators/ztwim/oobtkube.yaml
```

### Specify Callback IP

```bash
python3 scripts/automate_oobtkube_scan.py --callback-ip 10.215.98.167
```

### Full Example

```bash
python3 scripts/automate_oobtkube_scan.py \
  --config config/operators/ztwim/oobtkube.yaml \
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
cp config/operators/example/oobtkube.yaml config/operators/my-operator/oobtkube.yaml
```

Edit `config/operators/my-operator/oobtkube.yaml`:

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
python3 scripts/automate_oobtkube_scan.py --config config/operators/my-operator/oobtkube.yaml
```

### Step 4: View Results

Results are stored per operator:

```
results/oobtkube/
├── ztwim/                          # ZTWIM operator runs
│   └── 2026-03-02_10-30-00/
│       └── oobtkube-*-results.sarif
└── my-operator/                    # Your operator runs
    └── 2026-03-02_11-00-00/
        └── oobtkube-*-results.sarif
```

---

## ZAP API Scanning (Optional)

ZAP scans the Kubernetes API for HTTP-level issues. Results stored in `results/zap/flat/<operator>/<timestamp>/` (like `results/oobtkube/`).

### Token handling (safe by design)

On-disk ZAP template files (`zap-operator.yaml`, `zap-operands.yaml`) contain **placeholders** (`Bearer <INJECTED_AT_RUNTIME>`, `<API_SERVER>`). The automation:

1. Fetches a fresh token (`oc create token` or `ZAP_KUBERNETES_TOKEN` env var).
2. Renders runtime configs in a **temporary directory** with the real API URL + token.
3. Mounts only the temp files into the Podman/RapiDAST container.
4. **Auto-deletes** the temp directory in a `finally` block when the scan finishes (or fails).

Templates are never modified — `git diff` stays clean after every scan, and no credentials can leak into version control.

**Automated (recommended):**

```bash
python3 scripts/automate_zap_scan.py --config config/operators/ztwim/zap/zap.yaml
```

Runs both operator and operands scans, stores SARIF in `results/zap/flat/ztwim/<timestamp>/zap-operator-results.sarif` and `zap-operands-results.sarif`, and uploads to GCP if configured.

**Debug with --skip-config-update:** pass this flag to mount the template YAMLs as-is (you must first replace the placeholders manually). Mainly for one-off debugging:

```bash
python3 run_all_dast_scans.py --operator ztwim --skip-zap-config-update
# or: python3 scripts/automate_zap_scan.py --config config/operators/ztwim/zap/zap.yaml --skip-config-update
```

**Note:** `scripts/update-zap-config.sh` is deprecated. The Python automation handles token injection via temp files now.

**Manual (step-by-step) (deprecated — prefer automated flow above):**

```bash
mkdir -p results/zap/rapidast && chmod o+w results/zap/rapidast
podman run -v $(pwd)/config/operators/ztwim/zap/zap-operator.yaml:/opt/rapidast/config/config.yaml:Z \
  -v $(pwd)/results/zap/rapidast/:/opt/rapidast/results/:Z \
  quay.io/redhatproductsecurity/rapidast:latest
podman run -v $(pwd)/config/operators/ztwim/zap/zap-operands.yaml:/opt/rapidast/config/config.yaml:Z \
  -v $(pwd)/results/zap/rapidast/:/opt/rapidast/results/:Z \
  quay.io/redhatproductsecurity/rapidast:latest
```

**Upload ZAP results to GCP:**

```bash
python3 exports/upload_zap_results.py --config config/operators/ztwim/zap/zap.yaml
python3 exports/upload_zap_results.py --config config/operators/ztwim/zap/zap.yaml --all
```

Uploads the latest `results/zap/flat/ztwim/<timestamp>/` (or all with `--all`) as a gzipped tarball to GCS.

---

## Trivy k8s (Optional)

RapiDAST [`generic_trivy`](https://github.com/RedHatProductSecurity/rapidast/blob/development/config/config-template-trivy-k8s-scan.yaml) runs `trivy k8s` against the cluster using your kubeconfig (mounted read-only at `/opt/rapidast/.kube/config`). Flat SARIF: `results/trivy/flat/<operator>/<timestamp>/`.

**Prerequisites:** `oc` login (or a valid `KUBECONFIG`), Podman, and namespace scope in [`trivy-k8s.yaml`](config/operators/ztwim/trivy/trivy-k8s.yaml) aligned with the operator install.

The kubeconfig bind mount uses Podman `:ro,Z` so **SELinux** (Fedora/RHEL) allows Trivy to read the file inside the container. If you still see `permission denied` on `/opt/rapidast/.kube/config`, run `restorecon -Fv` on the kubeconfig path or see `man podman-run` (volume `:Z`).

```bash
python3 scripts/automate_trivy_scan.py --config config/operators/ztwim/trivy/trivy.yaml
# or:  --kubeconfig /path/to/kubeconfig
```

`run_all_dast_scans.py` runs Trivy automatically when `config/operators/<operator>/trivy/trivy.yaml` exists; **`--skip-trivy`** skips it.

---

## Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--config`, `-c` | config/operators/ztwim/oobtkube.yaml | Path to operator config YAML |
| `--namespace` | from config | Operator namespace (overrides config) |
| `--callback-ip` | auto-detect | IP reachable from cluster pods |
| `--duration` | 120 | Scan duration per CR (seconds) |
| `--port` | 12345 | Callback listener port |
| `--download-rapidast` | false | Clone RapiDAST from GitHub if not present |
| `--skip-export` | false | Skip CR export; use existing oobtkube-config/ |

---

## Config File Structure

```yaml
# Framework (optional; defaults are used if omitted)
framework:
  rapidastRepo: "https://github.com/RedHatProductSecurity/rapidast.git"
  rapidastDir: "rapidast"
  configDir: "oobtkube-config"
  resultBaseDir: "results/oobtkube"
  oobtkubeScript: "scanners/generic/tools/oobtkube.py"
  oobtkubeLogLevel: debug   # optional; default in code is debug if omitted

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
    keyFile: "secrets/rapidast-sa-operators-ztwim_key.json"
    bucketName: "secaut-bucket"
    directory: "operators/ztwim"
```

---

## Output Structure

Each run creates a **timestamped directory** under `results/oobtkube/<operator>/`. CR configs are stored **per operator** in `oobtkube-config/<operator>/` so multiple operators can be scanned without mixing files:

```
dast-scan-automation/
├── run_all_dast_scans.py     # Main entry point: run all scans + upload combined to GCS
├── scripts/
│   ├── automate_oobtkube_scan.py  # OOBTKUBE scan automation
│   ├── automate_zap_scan.py   # ZAP scan automation
│   ├── automate_trivy_scan.py # Trivy k8s scan automation
│   ├── clean-artifacts.sh     # Remove results, caches, stale keys
│   └── update-zap-config.sh   # DEPRECATED — automation handles token injection
├── dast/                      # Shared framework
│   ├── config.py, oc.py, utils.py
│   ├── oobtkube.py, zap.py (runtime config rendering), trivy.py
├── config/
│   └── operators/             # Per-operator bundles
│       ├── ztwim/
│       │   ├── oobtkube.yaml
│       │   ├── zap/
│       │   │   ├── zap.yaml, zap-operator.yaml, zap-operands.yaml
│       │   │   └── dast-zap-setup.yaml   # SA/RBAC bootstrap
│       │   └── trivy/
│       │       ├── trivy.yaml            # Trivy orchestration
│       │       └── trivy-k8s.yaml        # RapiDAST generic_trivy config
│       ├── eso/
│       │   └── oobtkube.yaml
│       └── example/
│           └── oobtkube.yaml  # Template for new operators
├── exports/
│   ├── gcs_export.py          # GCS upload logic
│   └── upload_zap_results.py  # ZAP results upload
├── rapidast/                  # Cloned by --download-rapidast
├── oobtkube-config/           # Per-operator CR YAML files (gitignored)
│   ├── ztwim/
│   │   └── zerotrustworkloadidentitymanagers-cr-oobtkube.yaml
│   └── eso/
│       └── externalsecrets-cr-oobtkube.yaml
├── results/oobtkube/          # OOBTKUBE scan results
│   └── ztwim/2026-04-02_18-54-14/
│       ├── oobtkube-*-results.sarif
│       └── oobtkube-*-run.log
├── results/zap/
│   ├── flat/ztwim/<timestamp>/        # flat SARIF + HTML copies
│   │   ├── zap-operator-results.sarif
│   │   ├── zap-operands-results.sarif
│   │   └── zap-operands-report.html
│   └── rapidast/ZTWIM-*-ZAP/DAST-*-RapiDAST-*/  # RapiDAST native output
└── results/trivy/
    ├── flat/ztwim/<timestamp>/        # flat Trivy SARIF
    │   └── trivy-k8s-results.sarif
    └── rapidast/ZTWIM-Trivy-K8s/DAST-*-RapiDAST-*/
```

---

## What the Script Does

1. **Loads config** — Reads operator settings (namespace, CRs) from YAML
2. **Ensures RapiDAST** — Clones from GitHub only if not present
3. **Checks prerequisites** — oc CLI, cluster access, namespace, pods
4. **Migrate (one-time)** — Moves `*-cr-oobtkube.yaml` from `oobtkube-config/` root into `oobtkube-config/<operator>/` if present (legacy flat layout)
5. **Restore CRs** — Restores CRs from `oobtkube-config/<operator>/` so cluster starts clean
6. **Exports CRs** — Exports configured CRs to `oobtkube-config/<operator>/`
7. **Runs OOBTKUBE** — Scans each CR in the operator's config dir for command injection
8. **Stores results** — Saves SARIF files in `results/oobtkube/<operator>/<timestamp>/`
9. **GCS export** — Optionally uploads results if configured

---

## View Results

```bash
# View a specific run
cat results/oobtkube/ztwim/2026-03-02_10-30-00/oobtkube-*-results.sarif | jq .

# List all runs for an operator
ls -la results/oobtkube/ztwim/
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
| Podman/Docker not found | ZAP requires Podman or Docker; install and ensure in PATH |
| ZAP Operator scan timeout, no SARIF | Operator scan (61+ URLs) can take 60-90 min. Set `zap.timeoutMinutes: 90` (or higher) in `config/operators/ztwim/zap/zap.yaml` |
| ZAP **403 Forbidden** on APIs, 0 meaningful findings | Default `oc create token default -n default` lacks RBAC. Use `export ZAP_KUBERNETES_TOKEN=$(oc whoami -t)` or a dedicated SA — see [docs/ZAP-RBAC-and-Review-Notes.md](docs/ZAP-RBAC-and-Review-Notes.md) |
| OOBTKUBE empty SARIF | See `oobtkube-*-run.log` next to SARIF; default log level is **debug**; use `--log-level info` or `oobtkubeLogLevel: info` for less verbosity |
| ZAP operator **HTML missing**, operands HTML OK | ZAP's OpenAPI parser crashes on the `operator.openshift.io/v1alpha1` spec (contains CRDs that trigger parser bugs). Operands (`spire.spiffe.io/v1alpha1`) parse fine. See [Known Limitations](#known-limitations) |
| Trivy **permission denied** on kubeconfig | SELinux blocks the Podman mount. Run `restorecon -Fv $KUBECONFIG` or ensure the `:ro,Z` volume flag is used (already set in `dast/trivy.py`) |
| Cannot remove `results/` or `zap-op/` | Use `scripts/clean-artifacts.sh` (handles Podman-owned dirs via `podman unshare`), or: `sudo restorecon -Rv results/ && rm -rf results/` |

See **[docs/ZAP-RBAC-and-Review-Notes.md](docs/ZAP-RBAC-and-Review-Notes.md)** for security-review follow-up (403 pattern, HTML reports, RBAC examples).

---

## Known Limitations

| Area | Issue | Status / Workaround |
|------|-------|---------------------|
| **ZAP operator scan** | ZAP's OpenAPI addon crashes when parsing the `/openapi/v3/apis/operator.openshift.io/v1alpha1` spec. The spec is valid JSON (18 paths, ~459 KB) but includes CRD schemas that trigger a parser bug (`NullPointerException` or silent exit during `Job openapi`). **Result:** `return_code: 1`, empty SARIF, no HTML report. The **operands** scan (`spire.spiffe.io/v1alpha1`) is unaffected. | Trim the spec to ZTWIM-only paths before feeding to ZAP (planned), or wait for a RapiDAST/ZAP parser fix. OOBTKUBE and Trivy already cover operator CRDs. See [docs/ZAP-RBAC-and-Review-Notes.md](docs/ZAP-RBAC-and-Review-Notes.md). |
| **Aggregated `/openapi/v2`** | The full v2 spec (~4+ MB) can cause ZAP to OOM or timeout during import, even with `memMaxHeap: 8192m`. | Use per-group v3 endpoints where possible. |

---

## Rerunning

The script can be **rerun repeatedly** without manual cleanup:

- **Restore precheck** — Before each run, CRs are restored from `oobtkube-config/<operator>/`
- **RapiDAST** — Never re-cloned if already present
- **Results** — Each run creates a new timestamped directory; previous results are kept
- **Multi-operator** — Each operator uses its own config dir; ZTWIM and ESO scans do not interfere

---

## Example: ZTWIM Operator (Default Config)

The default `config/operators/ztwim/oobtkube.yaml` is configured for ZTWIM:

- **Operator:** ZeroTrustWorkloadIdentityManager
- **Operands:** SpireServer, SpireAgent, SpiffeCSIDriver, SpireOIDCDiscoveryProvider
- **Namespace:** zero-trust-workload-identity-manager
