# Operator config layout

Each operator is a directory under `config/operators/<name>/`.

**OOBTKUBE CR exports (runtime, not under `config/`):** [`oobtkube-config/<name>/`](../oobtkube-config/README.md) — holds `*-cr-oobtkube.yaml` files produced from the cluster per `cr_configs` in `oobtkube.yaml`. Gitignored except [`oobtkube-config/README.md`](../oobtkube-config/README.md).

| Path | Purpose |
|------|---------|
| `oobtkube.yaml` | OOBTKUBE scan (namespace, CRs, callback, optional GCS). Sets `framework.configDir` (default `oobtkube-config`) and `resultBaseDir` (`results/oobtkube`). |
| `zap/` | Optional. All ZAP / RapiDAST files for this operator. Omit the whole folder if you only run OOBTKUBE (e.g. ESO today). |
| `zap/zap.yaml` | ZAP orchestration: image, timeouts, `zap.configs` paths, GCS for ZAP uploads. |
| `zap/zap-operator.yaml` | RapiDAST config for the operator API groups scan. |
| `zap/zap-operands.yaml` | RapiDAST config for the operands API groups scan. |
| `trivy/` | Optional. Trivy k8s misconfiguration via RapiDAST (`generic_trivy`). |
| `trivy/trivy.yaml` | Orchestration: path to `trivy-k8s.yaml`, image, timeout. |
| `trivy/trivy-k8s.yaml` | RapiDAST config: `trivy k8s` inline command and `application.shortName`. |

**Defaults:** `run_all_dast_scans.py --operator <name>` uses `oobtkube.yaml` and `zap/zap.yaml` when present; runs Trivy when `trivy/trivy.yaml` exists (unless `--skip-trivy`).
