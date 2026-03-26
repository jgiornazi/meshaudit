# meshaudit — Week 2 Tasks

**Sprint Goal:** `meshaudit scan --output json` emits a full structured report with AuthorizationPolicy findings and posture score.

---

## Task 1 — AuthorizationPolicy Risk Rule Engine (`internal/audit/authz.go`) ✅
- [x] List all `security.istio.io/v1beta1/AuthorizationPolicy` resources across target namespaces
- [x] Implement the 4 risk rules from the PRD:
  - **WARN** — `from` block contains wildcard principal (`"*"`) — grants access to any mesh service
  - **WARN** — Policy exists but has no `from` principals at all — open to any caller
  - **WARN** — Rule uses wildcard methods (`"*"`) or wildcard paths (`"/*"`) combined with broad principals
  - **FAIL** — Policy is in `DENY` action with no `selector` — can silently block all namespace traffic
  - **INFO** — Policy present with no issues detected
- [x] Return `[]AuthzFinding` with fields: `Service`, `Namespace`, `Severity`, `Detail`, `SuggestedFix`
- [x] Handle RBAC 403 errors gracefully (same pattern as mTLS lister)

## Task 2 — Posture Score (`internal/audit/score.go`) ✅
- [x] Extract score logic out of `internal/report/pretty.go` into its own package file
- [x] Implement the full PRD formula (currently only mTLS half exists):
  ```
  Score = 100 − (DISABLED×20) − (PERMISSIVE×10) − (AUTHZ_WARN×5) − (AUTHZ_FAIL×15)
  ```
- [x] Floor score at 0
- [x] Return score + band: `≥ 90 → GOOD`, `70–89 → FAIR`, `< 70 → POOR`
- [x] Update `PrintSummary` in `pretty.go` to pass authz findings into the score calculation

## Task 3 — JSON Output (`internal/report/json.go`) ✅
- [x] Define a `Report` struct matching the PRD JSON schema (10.3):
  - Top-level: `cluster`, `scanned_at`, `namespace`, `score`, `score_band`, `summary`
  - `findings[]`: `service`, `namespace`, `type` (`mtls`/`authz`), `severity`, `detail`, `suggested_fix`
- [x] Marshal using `encoding/json` (stdlib only — no external deps)
- [x] Wire `--output json` flag in `cmd/scan.go` to call `report.PrintJSON` instead of `report.PrintMTLS`
- [x] JSON output must be valid and parseable by `jq`

## Task 4 — Pretty Renderer: AuthorizationPolicy Section (`internal/report/pretty.go`) ✅
- [x] Add `PrintAuthz(w io.Writer, findings []audit.AuthzFinding)` function
- [x] Severity icons + colors:
  - INFO → green `■` — "policy present, no issues"
  - WARN → yellow `■` — finding detail + suggested fix hint
  - FAIL → red `■` — finding detail + suggested fix hint
- [x] Wire into `cmd/scan.go` so authz section prints after mTLS section

## Task 5 — `--fail-on-warn` Exit Code Logic ✅
- [x] `--fail-on-warn` flag implemented — exits 1 if any WARN or FAIL findings exist
- [x] Exit code 0 = all clear (or `--fail-on-warn` not set)
- [x] Exit code 2 = meshaudit error (bad kubeconfig, API unreachable) — already implemented
- [x] `--min-score` flag: if final score is below threshold → exit code 1

## Task 6 — Unit Tests (`internal/audit/authz_test.go`, `internal/audit/score_test.go`) ✅
- [x] Tests covering all 4 AuthorizationPolicy risk rules:
  - Wildcard principal fires WARN
  - Missing `from` block fires WARN
  - Wildcard method+path with broad principal fires WARN
  - DENY action with no selector fires FAIL
  - Clean policy returns INFO
- [x] Tests for score formula:
  - All STRICT + clean authz = 100
  - Mixed mTLS + authz findings = correct weighted deduction
  - Score floors at 0 (cannot go negative)
  - Band boundary conditions (90/89, 70/69)
- [x] **97.9% coverage** on `internal/audit` — hard ceiling is `authzRBACError`'s `os.Exit(2)` call (same untestable pattern as Week 1's `fatal()`)

## Task 7 — GitHub Actions CI (`.github/workflows/ci.yml`) ✅
- [x] Trigger on: `push` to `main`, `pull_request`
- [x] Jobs:
  - `test`: `go test ./... -race -coverprofile=coverage.out`
  - `vet`: `go vet ./...`
  - `lint`: `golangci-lint run` (pinned to v1.64.8)
- [x] Coverage gate: fails PR if `internal/audit` drops below 97%
- [x] Go module cache between runs

---

## New Files This Week
| File | Purpose |
|------|---------|
| `internal/audit/authz.go` | AuthorizationPolicy lister + risk rules |
| `internal/audit/authz_test.go` | Unit tests for all 4 risk rules |
| `internal/audit/score.go` | Posture score formula (extracted + expanded) |
| `internal/audit/score_test.go` | Score formula unit tests |
| `internal/report/json.go` | JSON report marshaller |
| `.github/workflows/ci.yml` | GitHub Actions CI pipeline |

## Files Modified This Week
| File | Change |
|------|--------|
| `internal/report/pretty.go` | Add `PrintAuthz`, remove inline score logic |
| `cmd/scan.go` | Wire authz scan, JSON output branch, exit code logic |

---

## Week 2 Deliverable ✅
`meshaudit scan --output json` emits a complete structured JSON report including mTLS findings, AuthorizationPolicy findings, posture score, and summary — parseable by `jq` and suitable for SIEM ingestion.

```bash
meshaudit scan --namespace production --output json | jq '.score'
meshaudit scan --namespace production --fail-on-warn  # exits 1 if any WARN/FAIL
meshaudit scan --namespace production --min-score 90  # exits 1 if score < 90
```

---

## Out of Scope (Week 3)
- GoReleaser cross-compilation config
- Homebrew tap formula
- README.md + CONTRIBUTING.md
- envtest integration tests (deferred from Week 2 per complexity)
- Demo GIF recording
- v1.0.0 tag + GitHub Release
