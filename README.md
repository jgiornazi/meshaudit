# meshaudit

Lightweight CLI tool for auditing Istio service mesh security posture. Scans mTLS configuration and AuthorizationPolicy rules across all workloads in a Kubernetes cluster and emits a prioritized, actionable security report in under 30 seconds.

![CI](https://github.com/jgiornazi/meshaudit/actions/workflows/ci.yml/badge.svg)

---

## Install

**Homebrew (macOS / Linux)**
```bash
brew tap jgiornazi/meshaudit
brew install meshaudit
```

**Direct download**

Download a pre-built binary from [GitHub Releases](https://github.com/jgiornazi/meshaudit/releases), verify the checksum, and install:
```bash
# Example: macOS arm64
curl -LO https://github.com/jgiornazi/meshaudit/releases/latest/download/meshaudit_v1.0.0_darwin_arm64.tar.gz
sha256sum --check checksums.txt
tar -xzf meshaudit_v1.0.0_darwin_arm64.tar.gz
mv meshaudit /usr/local/bin/
```

**Build from source**
```bash
go install github.com/jgiornazi/meshaudit@latest
```

---

## Quick Start

```bash
# Scan all namespaces
meshaudit scan

# Scan a single namespace
meshaudit scan --namespace production

# Output structured JSON (pipe to jq, SIEM, etc.)
meshaudit scan --output json | jq .score

# Fail CI if any WARN or FAIL findings
meshaudit scan --fail-on-warn

# Fail CI if posture score drops below 80
meshaudit scan --min-score 80
```

---

## Commands & Flags

### Commands

| Command   | Description |
|-----------|-------------|
| `scan`    | Scan mTLS posture and AuthorizationPolicies |
| `drift`   | Detect VirtualService drift vs local YAML (v1.1) |
| `version` | Print version and build metadata |

### Global Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--kubeconfig` | `$KUBECONFIG` or `~/.kube/config` | Path to kubeconfig |
| `--context` | current context | Kubernetes context to use |
| `--namespace`, `-n` | all namespaces | Limit scan to a single namespace |
| `--output` | `pretty` | Output format: `pretty` or `json` |
| `--fail-on-warn` | false | Exit code 1 if any WARN or FAIL findings exist |

### Scan Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--skip-namespaces` | — | Comma-separated namespaces to exclude |
| `--min-score` | 0 | Fail if posture score is below this threshold (0–100) |

### Drift Flags (v1.1)

| Flag | Default | Description |
|------|---------|-------------|
| `--git-path` | — | Path to local directory of Istio YAML manifests (required) |

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed; all findings are INFO or better (or `--fail-on-warn` not set) |
| `1` | WARN or FAIL findings detected and `--fail-on-warn` is set; or score below `--min-score` |
| `2` | Error — bad kubeconfig, API server unreachable, missing RBAC, etc. |

---

## Output Examples

### Pretty terminal

```
$ meshaudit scan --namespace production

meshaudit v1.0.0 | cluster: prod-us-west-2 | namespace: production
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

mTLS Posture
✅ payments-svc     strict mTLS
✅ auth-svc         strict mTLS
⚠️  inventory-svc   permissive mTLS — vulnerable to plaintext
❌ legacy-api       mTLS disabled — high risk

AuthorizationPolicy
✅ payments-svc     policy present, no issues
⚠️  orders-svc      allows wildcard principal (*)
⚠️  cart-svc        no principal selector defined

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Security Posture Score: 62 / 100 [POOR]
2 PASS | 2 WARN | 1 FAIL
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### JSON output (`--output json`)

```json
{
  "cluster": "prod-us-west-2",
  "scanned_at": "2025-09-12T14:23:01Z",
  "namespace": "production",
  "score": 62,
  "score_band": "POOR",
  "summary": { "pass": 2, "warn": 3, "fail": 1 },
  "findings": [
    {
      "service": "inventory-svc",
      "namespace": "production",
      "type": "mtls",
      "severity": "WARN",
      "detail": "PeerAuthentication mode: PERMISSIVE",
      "suggested_fix": "Set PeerAuthentication mode to STRICT to enforce mTLS on all inbound traffic"
    },
    {
      "service": "orders-svc",
      "namespace": "production",
      "type": "authz",
      "severity": "WARN",
      "detail": "AuthorizationPolicy allows wildcard principal (*)",
      "suggested_fix": "Replace wildcard with explicit service account principals"
    }
  ]
}
```

---

## CI Integration

### GitHub Actions

```yaml
- name: meshaudit security gate
  run: |
    meshaudit scan \
      --namespace production \
      --fail-on-warn \
      --min-score 80 \
      --output json | tee meshaudit-report.json
```

Upload the report as a CI artifact for audit trail:
```yaml
- uses: actions/upload-artifact@v4
  with:
    name: meshaudit-report
    path: meshaudit-report.json
```

### Exit code integration

meshaudit returns exit code `1` when `--fail-on-warn` is set and any WARN or FAIL findings are present, making it a clean pre-deployment gate in any CI system that checks exit codes.

---

## Scoring

meshaudit computes a 0–100 posture score after each scan:

```
Score = 100 − (DISABLED_COUNT × 20) − (PERMISSIVE_COUNT × 10)
            − (AUTHZ_WARN_COUNT × 5) − (AUTHZ_FAIL_COUNT × 15)
```

Score is floored at 0.

| Score | Band |
|-------|------|
| ≥ 90  | GOOD |
| 70–89 | FAIR |
| < 70  | POOR |

---

## Required RBAC

meshaudit is strictly read-only. The minimum ClusterRole required:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: meshaudit-reader
rules:
- apiGroups: [""]
  resources: ["services", "namespaces"]
  verbs: ["get", "list"]
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list"]
- apiGroups: ["security.istio.io"]
  resources: ["peerauthentications", "authorizationpolicies"]
  verbs: ["get", "list"]
- apiGroups: ["networking.istio.io"]   # v1.1 drift only
  resources: ["virtualservices"]
  verbs: ["get", "list"]
```

If meshaudit encounters a permissions error it prints the exact `kubectl apply` command needed to grant access and exits with code 2.

---

## Drift Detection (v1.1)

`meshaudit drift` compares live Istio VirtualService resources in your cluster against a local directory of YAML manifests (your desired state from Git). It surfaces GitOps configuration drift before it causes incidents.

### Usage

```bash
# Compare all VirtualServices against local manifests
meshaudit drift --git-path ./manifests

# Scope to a single namespace
meshaudit drift --git-path ./manifests --namespace production

# Get structured JSON output
meshaudit drift --git-path ./manifests --output json | jq .drift_results

# Fail CI if any drift is detected
meshaudit drift --git-path ./manifests --fail-on-warn
```

### Pretty terminal output

```
VirtualService Drift
  ■  production/reviews-vs            IN SYNC
  ■■ production/ratings-vs            DRIFT DETECTED
        └─ spec.http: live=[{timeout:10s}], desired=[{timeout:5s}]
  ■  production/old-vs                LIVE ONLY (not in git)
  ■  staging/new-feature-vs           MANIFEST ONLY (not deployed)
```

### JSON output (`--output json`)

```json
{
  "cluster": "prod-us-west-2",
  "scanned_at": "2025-09-12T14:23:01Z",
  "namespace": "production",
  "drift_results": [
    {
      "name": "ratings-vs",
      "namespace": "production",
      "status": "DRIFT_DETECTED",
      "diffs": [
        { "field": "spec.http", "live": [{"timeout": "10s"}], "desired": [{"timeout": "5s"}] }
      ]
    },
    {
      "name": "reviews-vs",
      "namespace": "production",
      "status": "IN_SYNC"
    }
  ]
}
```

### Drift status values

| Status | Meaning |
|--------|---------|
| `IN_SYNC` | Live and desired specs are identical |
| `DRIFT_DETECTED` | Both exist but specs differ; field-level diffs shown |
| `LIVE_ONLY` | VS exists in cluster but not in the manifest directory |
| `MANIFEST_ONLY` | VS exists in manifests but is not deployed |

### Notes

- Drift detection is strictly read-only — meshaudit never modifies cluster state
- Only `networking.istio.io/v1beta1` VirtualService resources are diffed
- Manifests may use `---` separators to include multiple VS documents per file
- Hidden directories (`.git`, `.github`) are skipped during manifest loading

---

## Limitations (v1.0)

- **Istio only** — no Linkerd, Consul Connect, or other mesh support
- **Read-only** — meshaudit never creates, modifies, or deletes any resource
- **mTLS + AuthorizationPolicy only** — no RBAC, ClusterRole, or NetworkPolicy auditing
- **No persistent state** — no database, server, or agent component
- **No GUI** — terminal and JSON output only

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, branch conventions, and how to add new audit rules.

---

## License

MIT — see [LICENSE](LICENSE).
