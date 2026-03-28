# meshaudit — Istio mTLS & AuthorizationPolicy Security Auditor for Kubernetes

| Field | Details |
|---|---|
| **Document Type** | Product Requirements Document |
| **Version** | 1.0 — Initial Release |
| **Tool Name** | meshaudit |
| **Author** | Principal Engineer, Service Mesh Traffic Engineering |
| **Language** | Go |
| **Target Release** | v1.0 — 3-week build cycle |
| **Distribution** | GitHub Releases + Homebrew Formula |
| **License** | MIT (Open Source) |
| **Status** | Draft — In Review |

---

## 1. Executive Summary

meshaudit is a lightweight, zero-dependency CLI tool written in Go that gives platform and infrastructure engineers instant visibility into the security posture of their Istio service mesh. By connecting to a live Kubernetes cluster via kubeconfig, meshaudit scans every service's mTLS configuration and AuthorizationPolicy rules, flags misconfigurations, and emits a prioritized security report — all in under 30 seconds.

Service meshes introduce powerful security primitives, but they also introduce configuration surface area that is easy to mismanage at scale. A single service left in PERMISSIVE mTLS mode or an AuthorizationPolicy with a wildcard principal can silently expose internal traffic to lateral movement. meshaudit makes these risks auditable, reportable, and CI-friendly.

**Problem:** Teams operating Istio at scale lack a fast, scriptable tool to audit mTLS posture and AuthorizationPolicy hygiene across all workloads. Manual inspection via `kubectl` does not scale and produces no structured output.

**Solution:** meshaudit codifies Istio security best practices into a single binary. Run it locally, in CI, or as a pre-deployment gate to catch misconfigurations before they reach production.

---

## 2. Problem Statement

### 2.1 Background

Istio provides mutual TLS (mTLS) and policy-based access control (AuthorizationPolicy) as core security controls for service-to-service communication. However, the declarative nature of Kubernetes means that security posture degrades silently over time:

- Services may be added to the mesh in PERMISSIVE mode (accepting plaintext) without a follow-up migration to STRICT.
- AuthorizationPolicies may be authored with overly broad principals (`"*"`) or missing `from` selectors due to time pressure.
- There is no built-in Kubernetes or Istio tool that produces a cluster-wide security summary.
- Existing solutions (Kiali, Grafana dashboards) require running infrastructure and are not scriptable.

### 2.2 Target Users

| Persona | Role | Primary Need |
|---|---|---|
| Platform Engineer | Owns cluster infrastructure, mesh config | Cluster-wide mTLS posture report |
| Security Engineer | Reviews posture, manages compliance | Risky policy detection, JSON output for SIEM |
| Staff / Principal SWE | Operates team-owned services on shared mesh | Namespace-scoped scan, fast feedback |
| SRE / DevOps | Runs CI/CD pipelines, deployment gates | Exit code on failure, CI integration |

---

## 3. Goals & Non-Goals

### 3.1 Goals

- Provide a single-command mTLS posture scan across all namespaces or a scoped namespace.
- Flag AuthorizationPolicy configurations that violate least-privilege principles.
- Emit a human-readable terminal report (color + icons) and a structured JSON report via flag.
- Produce a summary security posture score (0–100) suitable for dashboards and reporting.
- Include a `suggested_fix` field on every finding — a plain-English hint telling the operator exactly what to change (e.g. "Set PeerAuthentication mode to STRICT"). The tool never applies fixes; it only describes them.
- Integrate cleanly into CI/CD pipelines via predictable exit codes.
- Distribute as a single static binary — no runtime dependencies, no sidecar, no agent.
- Build in the open (MIT license) to support community adoption and contribution.

### 3.2 Non-Goals (v1)

- No Envoy / non-Istio mesh support (Linkerd, Consul Connect) — future roadmap only.
- No cluster mutation — meshaudit is strictly read-only and will never create, update, or delete any Kubernetes or Istio resource.
- No RBAC / ClusterRole auditing — scoped to mTLS + AuthorizationPolicy.
- No persistent state, database, or server-side component.
- No Helm chart / in-cluster deployment mode.
- No GUI, web dashboard, or Slack integration in v1.

---

## 4. Feature Requirements

### 4.1 v1.0 — Core Audit Engine

#### 4.1.1 mTLS Posture Scanner

meshaudit inspects PeerAuthentication resources (mesh-wide, namespace-scoped, and workload-scoped) and maps each service to one of three mTLS posture states:

| State | Meaning |
|---|---|
| `STRICT` | Service enforces mTLS on all inbound traffic. All-clear. |
| `PERMISSIVE` | Service accepts both mTLS and plaintext. Vulnerable to downgrade attacks. |
| `DISABLED` | mTLS explicitly disabled. Plaintext only. Highest risk. |

Resolution logic follows Istio's policy precedence: workload-scoped > namespace-scoped > mesh-wide. If no PeerAuthentication applies, the tool uses the mesh-wide default (PERMISSIVE in most installations).

#### 4.1.2 AuthorizationPolicy Auditor

meshaudit scans all AuthorizationPolicy resources and applies the following risk rules:

- **WARN:** Rule includes a wildcard principal (`"*"`) in the `from` block — grants access to any service in the mesh.
- **WARN:** AuthorizationPolicy exists but has no `from` principals specified — open to any caller within the mesh.
- **WARN:** Rule uses wildcard methods (`"*"`) or wildcard paths (`"/*"`) in combination with broad principals.
- **FAIL:** AuthorizationPolicy is in DENY mode with no selector — can silently block all traffic to a namespace.
- **INFO:** AuthorizationPolicy present with no issues detected — acknowledged and marked as reviewed.

#### 4.1.3 Output Modes

Controlled via CLI flags. Default is pretty terminal.

| Flag | Format | Use Case |
|---|---|---|
| *(default)* | Pretty terminal (ANSI color + icons) | Interactive CLI use, fast human review |
| `--output json` | Structured JSON | CI/CD pipelines, SIEM ingestion, scripting |

#### 4.1.4 Security Posture Score

After scanning, meshaudit computes a 0–100 score based on the following weighted formula:

```
Score = 100 − (DISABLED_COUNT × 20) − (PERMISSIVE_COUNT × 10)
            − (AUTHZ_WARN_COUNT × 5) − (AUTHZ_FAIL_COUNT × 15)
```

Score is floored at 0.

| Score | Band |
|---|---|
| ≥ 90 | GOOD |
| 70–89 | FAIR |
| < 70 | POOR |

#### 4.1.5 Example Terminal Output

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

### 4.2 v1.1 — VirtualService Drift Detection

v1.1 introduces a `--drift` flag that compares live cluster VirtualService state against a local directory of YAML manifests (the "desired state" from Git). This enables detection of configuration drift between what is deployed and what is committed.

- Accepts a `--git-path` flag pointing to a local directory of Istio YAML manifests.
- Diffs VirtualService resources: host routing rules, weights, retries, timeouts, fault injection.
- Emits a `DRIFT DETECTED` or `IN SYNC` result per VirtualService with a field-level diff summary.
- Supports `--namespace` scoping for monorepo layouts where manifests are per-team.
- JSON output mode emits a structured diff object suitable for GitOps tooling.

> **v1.1 Note:** Drift detection is read-only. meshaudit never modifies cluster state. The tool is a diagnostic, not a reconciler.

---

## 5. CLI Design & Commands

### 5.1 Command Structure

```
meshaudit [flags]

Commands:
  scan      Scan mTLS posture and AuthorizationPolicies (v1.0)
  drift     Detect VirtualService drift vs local YAML (v1.1)
  version   Print version and build metadata

Global Flags:
  --kubeconfig string   Path to kubeconfig (default: $KUBECONFIG or ~/.kube/config)
  --context string      Kubernetes context to use
  --namespace string    Limit scan to a single namespace (default: all)
  --output string       Output format: pretty | json (default: pretty)
  --fail-on-warn        Exit with code 1 if any WARN or FAIL findings exist
  --version             Print version

Scan Flags:
  --skip-namespaces     Comma-separated namespaces to exclude
  --min-score int       Fail if posture score is below this threshold (0-100)

Drift Flags (v1.1):
  --git-path string     Path to local directory of Istio YAML manifests (required)
```

### 5.2 Exit Codes

| Code | Meaning | When |
|---|---|---|
| `0` | Success | Scan completed. All findings are INFO or better (or `--fail-on-warn` not set). |
| `1` | Findings | WARN or FAIL findings detected and `--fail-on-warn` flag is set. |
| `2` | Error | meshaudit encountered an error (bad kubeconfig, API server unreachable, etc.). |

---

## 6. Technical Architecture & Stack

### 6.1 Core Technology Choices

| Component | Choice | Rationale |
|---|---|---|
| Language | Go 1.22+ | Single binary compilation, fast startup, strong Kubernetes ecosystem. |
| Kubernetes Client | `k8s.io/client-go` | Official Go client; supports dynamic resource listing for CRDs. |
| Istio CRD Bindings | `istio.io/client-go` | Official typed Go bindings for PeerAuthentication, AuthorizationPolicy, VirtualService. |
| CLI Framework | `github.com/spf13/cobra` | De facto standard for Go CLIs; subcommands, flags, help text. |
| Terminal Output | `github.com/fatih/color` | Lightweight ANSI color library; auto-detects TTY for CI-safe output. |
| JSON Output | `encoding/json` (stdlib) | No external dependency. Marshals internal report struct directly. |
| Build & Release | GoReleaser + GitHub Actions | Cross-compilation, checksums, GitHub Release assets, Homebrew formula generation. |
| Testing | `testing` (stdlib) + envtest | Unit tests for rule logic; envtest for integration against a real API server. |

### 6.2 Project Structure

```
meshaudit/
├── cmd/
│   ├── root.go          # Global flags, kubeconfig init
│   ├── scan.go          # scan subcommand
│   └── drift.go         # drift subcommand (v1.1)
├── internal/
│   ├── audit/
│   │   ├── mtls.go      # PeerAuthentication resolution logic
│   │   ├── authz.go     # AuthorizationPolicy risk rules
│   │   └── score.go     # Posture score calculation
│   ├── k8s/
│   │   └── client.go    # kubeconfig + client-go init
│   └── report/
│       ├── pretty.go    # Terminal renderer
│       └── json.go      # JSON marshaller
├── drift/               # VirtualService diff engine (v1.1)
│   ├── loader.go        # Load local YAML manifests
│   └── diff.go          # Diff live vs desired state
├── .goreleaser.yaml
├── Makefile
└── README.md
```

### 6.3 Cross-Compilation & Distribution

GoReleaser handles cross-compilation and release artifact generation. meshaudit v1.0 ships binaries for:

- `linux/amd64` (standard server target)
- `linux/arm64` (Graviton, ARM cloud instances)
- `darwin/amd64` (Intel macOS)
- `darwin/arm64` (Apple Silicon)

A Homebrew tap formula is published to a companion repository and generated automatically by GoReleaser on each tagged release:

```bash
brew tap jgiornazi/meshaudit
brew install meshaudit
```

---

## 7. Three-Week Milestone Plan

The v1.0 build cycle is structured into three focused one-week sprints. Each sprint delivers a shippable increment.

### Week 1 — Foundation: Project scaffolding, Kubernetes connectivity, mTLS scanner

- Bootstrap Go module, Cobra CLI skeleton, Makefile targets (`build`, `test`, `lint`)
- Implement kubeconfig loader with context override support (`cmd/root.go`)
- List all namespaces and services via client-go; handle RBAC permission errors gracefully
- Implement PeerAuthentication lister with precedence resolution (workload > namespace > mesh)
- Map each service to STRICT / PERMISSIVE / DISABLED posture
- Unit tests for mTLS resolution logic with table-driven test cases
- Basic pretty-print terminal output with ANSI color and icons

**Deliverable:** `meshaudit scan` outputs mTLS posture for all services

### Week 2 — AuthorizationPolicy Auditor, JSON output, posture score, CI hardening

- Implement AuthorizationPolicy lister and risk rule engine (`authz.go`)
- Rule coverage: wildcard principal, missing from-principal, wildcard method+path, DENY with no selector
- Implement 0–100 posture score formula with GOOD / FAIR / POOR banding
- Implement `--output json` flag with structured report struct (marshalled via `encoding/json`)
- Implement `--fail-on-warn` flag and exit code logic
- Integration test suite using envtest with mock PeerAuthentication + AuthorizationPolicy fixtures
- GitHub Actions CI workflow: `go test`, `go vet`, `golangci-lint` on PR

**Deliverable:** `meshaudit scan --output json` emits full structured report with score

### Week 3 — Release pipeline, Homebrew formula, documentation, v1.0 tag

- GoReleaser config: `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64` targets
- SHA-256 checksums file and GitHub Release notes template
- Homebrew tap repository + formula (auto-generated by GoReleaser)
- `README.md`: install instructions, command reference, output examples, CI integration guide
- `CONTRIBUTING.md` + issue templates for the open-source repo
- Record a 90-second demo GIF of `meshaudit scan` against a local minikube cluster
- Tag v1.0.0, verify release artifacts, smoke-test Homebrew install

**Deliverable:** meshaudit v1.0.0 publicly released and installable via Homebrew

> **v1.1 Sprint (Week 4+):** VirtualService drift detection via `--drift --git-path ./manifests`. Estimated 1 additional week for diff engine, YAML loader, and output formatting.

---

## 8. Success Criteria

### 8.1 Functional Acceptance Criteria

| # | Criterion | Verification Method |
|---|---|---|
| 1 | `meshaudit scan` completes in < 30s on a 100-service cluster | Benchmarked against local minikube cluster |
| 2 | mTLS posture correctly resolves all three PeerAuthentication precedence levels | Table-driven unit tests covering all precedence permutations |
| 3 | All 5 AuthorizationPolicy risk rules fire correctly on crafted fixtures | Integration tests via envtest |
| 4 | `--output json` emits valid JSON parseable by `jq` with all required fields | CI pipeline `jq` validation step |
| 5 | `--fail-on-warn` returns exit code 1 when any WARN/FAIL present, 0 otherwise | Shell test in CI |
| 6 | Binary installs cleanly via `brew install meshaudit` on macOS arm64 + amd64 | Manual smoke test post-release |
| 7 | Binary size < 20MB on all platforms (static, no runtime deps) | GoReleaser artifact size check |

### 8.2 Quality Targets

- Unit test coverage: ≥ 80% on `internal/audit` package.
- Zero high-severity findings from `golangci-lint` on main branch.
- `README.md` covers install, all flags, output examples, and CI integration — verified by a dry-run on a clean machine before v1.0 tag.

---

## 9. Risks & Mitigations

| Risk | Severity | Mitigation |
|---|---|---|
| Istio CRD version skew between clusters (v1beta1 vs v1) | HIGH | Use dynamic client + version detection; fall back to v1beta1 if v1 unavailable. |
| RBAC permissions missing (cannot list CRDs in some clusters) | MED | Emit clear error with `kubectl` command to grant required ClusterRole. Document minimum RBAC spec in README. |
| Large clusters (1000+ services) cause slow scan times | LOW | Implement concurrent namespace scanning via goroutines with configurable worker pool. Benchmark and document. |
| Homebrew formula breaks on new GoReleaser versions | LOW | Pin GoReleaser version in GitHub Actions. Add smoke test job that runs `brew install` on CI. |

---

## 10. Appendix

### 10.1 Istio Resource Reference

meshaudit v1.0 reads the following Kubernetes / Istio resource types (read-only):

- `security.istio.io/v1beta1` — PeerAuthentication (mTLS policy)
- `security.istio.io/v1beta1` — AuthorizationPolicy (access control policy)
- `v1` — Service (namespace + selector mapping)
- `apps/v1` — Deployment (workload label resolution)
- `networking.istio.io/v1beta1` — VirtualService (v1.1 drift detection only)

### 10.2 Minimum RBAC Requirements

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
- apiGroups: ["networking.istio.io"] # v1.1 only
  resources: ["virtualservices"]
  verbs: ["get", "list"]
```

### 10.3 JSON Output Schema

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
      "suggested_fix": "Set PeerAuthentication mode to STRICT"
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
