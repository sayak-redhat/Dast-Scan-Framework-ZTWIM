# ZAP RBAC, Operator-scan policy, and 403 triage

## ZAP active-scan policies (RapiDAST)

RapiDAST ships ZAP policy packs under the upstream repo: [scanners/zap/policies](https://github.com/RedHatProductSecurity/rapidast/tree/main/scanners/zap/policies).

**This repo (ZTWIM example):**

| Config file | OpenAPI source | `activeScan.policy` | Rationale |
|-------------|----------------|---------------------|-----------|
| [`config/operators/ztwim/zap/zap-operator.yaml`](../config/operators/ztwim/zap/zap-operator.yaml) | **`/openapi/v3/apis/operator.openshift.io/v1alpha1`** (per-group; not full `/openapi/v2`) | **Kubernetes-API-scan** | **Prefer v3:** aggregated `/openapi/v2` is very large and often makes ZAP exit during `Job openapi` (no URLs, no HTML). If ZAP fails to parse this v3 URL (`NullPointerException`), try a newer RapiDAST/ZAP image, or temporarily raise `memMaxHeap` and retry v2 (slow). `urls.includes` narrows paths either way. |
| [`config/operators/ztwim/zap/zap-operands.yaml`](../config/operators/ztwim/zap/zap-operands.yaml) | `/openapi/v3/apis/spire.spiffe.io/v1alpha1` | **Kubernetes-API-scan** | Operands / SPIFFE API; v3 document parses cleanly with current ZAP. |

**Optional experiment:** In a branch, point `zap-operator.yaml` at the v3 OpenAPI URL and use **Operator-scan** if a future ZAP/RapiDAST release fixes the parser; compare scan time and SARIF. For `zap-operands.yaml`, set `Operator-scan` and compare versus `Kubernetes-API-scan`.

### Why operator `zap-*-report.html` can be missing while operands HTML exists

RapiDAST writes **`zap/zap-report.html`** only after the **full** ZAP automation plan succeeds (`openapi` → `activeScan` → `report` jobs). If the **operator** run exits early (for example **`Job openapi started`** then **ZAP exit code 1**), no report jobs run, so there is **no HTML** for that scan. The **operands** run often completes (`Job openapi added … URLs`, `activeScan`, `report generated … zap-report.html`), so **`zap-operands-report.html`** appears under `results/zap/flat/...`.

Common operator failures: OpenAPI **v3** parse errors on `operator.openshift.io/v1alpha1`, or **v2** (`/openapi/v2`) **too large** / memory or importer limits — check the Podman/RapiDAST log around the first **`openapi`** job for that config.

## 403 responses vs “bad parameters”

Automation renders **temporary** runtime configs (in a temp dir that is auto-deleted) with `application.url`, `scanners.zap.apiScan.target`, `scanners.zap.apiScan.apis.apiUrl`, and `Authorization: Bearer <token>` injected from `oc` — on-disk template YAMLs are never modified (unless `--skip-config-update` is passed, which mounts templates as-is). A high rate of **403 Forbidden** with **no 2xx/3xx** in the ZAP report can still mean:

1. **Genuine RBAC** — the identity behind the token cannot `get`/`list` the resources implied by the OpenAPI paths (expected for minimal SAs).
2. **Scope mismatch** — token is valid but not for the API groups in that config file.
3. **Less commonly** — malformed or non-applicable path segments; ZAP’s API scan should still show which URLs were requested.

**What to verify (review checklist):**

1. **Which identity is scanning?** Note `ZAP_SERVICE_ACCOUNT` / `ZAP_TOKEN_NAMESPACE` and `zap.serviceAccount` in [`zap/zap.yaml`](../config/operators/ztwim/zap/zap.yaml). Confirm with:
   - `oc auth can-i list zerotrustworkloadidentitymanagers.operator.openshift.io -n <namespace> --as=system:serviceaccount:<ns>:<sa>`
   - Repeat for operands API groups as needed.
2. **How many URLs and what status codes?** Open the HTML report under `results/zap/rapidast/<shortName>/DAST-*-RapiDAST-*/zap/zap-report.html` (flat copies: `results/zap/flat/<operator>/<timestamp>/*-report.html`). Check whether responses are **only** 403 or mixed; note URL count vs OpenAPI expansion.
3. **JSON detail:** `zap-report.json` / `zap-report.sarif.json` in the same tree for machine-readable summaries.
4. **Token freshness:** Tokens from `oc create token` expire (~1 hour). Stale tokens often fail consistently across URLs.

403-heavy results are **not** automatically “invalid parameters” from the tool; treat them as **authz / coverage** until RBAC and URL lists are reconciled with the report.

## Trivy (`trivy k8s`) vs ZAP

Trivy Kubernetes misconfiguration scans are **complementary** to ZAP API scans. They use cluster read access via kubeconfig (see [`scripts/automate_trivy_scan.py`](../scripts/automate_trivy_scan.py) and `config/operators/<op>/trivy/`). They do not replace ZAP for HTTP/API testing.

## RapidAST image and Trivy

The combined scan uses `quay.io/redhatproductsecurity/rapidast:latest`. On that image, **`/usr/local/bin/trivy`** and **`scanners/generic/tools/convert_trivy_k8s_to_sarif.py`** are present (RapiDAST `generic_trivy` pipeline). If your environment’s image tag differs or binaries are missing, update `rapidastImage` in [`trivy.yaml`](../config/operators/ztwim/trivy/trivy.yaml) or install Trivy per Aqua’s docs.
