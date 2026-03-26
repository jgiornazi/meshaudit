# meshaudit — Week 1 Tasks

**Sprint Goal:** `meshaudit scan` outputs mTLS posture for all services.

---

## Task 1 — Project Scaffolding ✅
- [x] `go mod init github.com/jgiornazi/meshaudit`
- [x] Cobra CLI skeleton: `cmd/root.go`, `cmd/scan.go`, `cmd/version.go`
- [x] `Makefile` with `build`, `test`, `lint` targets
- [x] Wire global flags: `--kubeconfig`, `--context`, `--namespace`, `--output`, `--fail-on-warn`

## Task 2 — Kubernetes Client (`internal/k8s/client.go`) ✅
- [x] Load kubeconfig with `--kubeconfig` flag override, falling back to `$KUBECONFIG` / `~/.kube/config`
- [x] Support `--context` override
- [x] Return typed client + Istio client from `istio.io/client-go`
- [x] Emit clear error (exit code 2) on bad kubeconfig or unreachable API server

## Task 3 — Namespace & Service Lister ✅
- [x] List all namespaces via `client-go` (or filter to `--namespace`)
- [x] List `v1/Service` resources across target namespaces
- [x] Handle RBAC 403 errors gracefully with a human-readable message + `kubectl` hint

## Task 4 — PeerAuthentication Lister + Precedence Resolution (`internal/audit/mtls.go`) ✅
- [x] List all `security.istio.io/v1beta1/PeerAuthentication` resources
- [x] Implement Istio precedence: **workload-scoped > namespace-scoped > mesh-wide**
- [x] If no policy applies, default to PERMISSIVE (mesh default)
- [x] Map each service to: `STRICT` / `PERMISSIVE` / `DISABLED`
- [x] Include a `suggested_fix` string per non-STRICT finding

## Task 5 — Unit Tests (`internal/audit/mtls_test.go`) ✅
- [x] Table-driven tests covering all precedence permutations:
  - Workload policy overrides namespace policy
  - Namespace policy overrides mesh-wide
  - No policy → PERMISSIVE default
  - Explicit DISABLED at workload scope
- [x] 26 tests passing, 100% coverage on `internal/audit`

## Task 6 — Pretty Terminal Renderer (`internal/report/pretty.go`) ✅
- [x] ANSI color + icons per state (green STRICT, yellow PERMISSIVE, red DISABLED)
- [x] Header: `meshaudit vX.Y.Z | cluster: <name> | namespace: <ns>`
- [x] mTLS section listing each service with its posture state
- [x] Auto-detect TTY (`fatih/color`) so CI output is clean

---

## Dependencies (pull Week 1)
- [x] `github.com/spf13/cobra`
- [x] `github.com/fatih/color`
- [x] `k8s.io/client-go`
- [x] `istio.io/client-go`

## Week 1 Deliverable
`meshaudit scan` connects to the cluster and prints mTLS posture for every service with ANSI color and icons.

---

## Out of Scope (Week 2+)
- AuthorizationPolicy auditing
- JSON output (`--output json`)
- Posture score (0–100)
- `--fail-on-warn` exit code logic
- envtest integration tests
- GitHub Actions CI
