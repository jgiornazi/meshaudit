# meshaudit — Testing Guide

This document explains the full testing strategy for meshaudit: what is tested, how each test works, why it is structured the way it is, and how to run everything.

---

## Overview

meshaudit has two distinct layers of testing:

| Layer | Location | Requires cluster? | Purpose |
|-------|----------|-------------------|---------|
| Unit & integration tests | `go test ./...` | No | Verify audit logic, report formatting, and CLI behaviour in isolation using in-memory fakes |
| Local functional tests | `scripts/local-test.sh` | Yes (minikube) | Verify the full binary end-to-end against real Kubernetes and Istio APIs |

The Go tests are the primary quality gate — they run on every CI push and must pass before any merge. The local test script is for pre-release validation on a real cluster.

---

## Part 1 — Go Unit & Integration Tests

Run with:
```bash
go test ./...
go test -race ./...         # with race detector (required before tagging)
go test -coverprofile=coverage.out ./...   # with coverage (gate: ≥ 75%)
```

---

### 1.1 `internal/audit` — Core audit logic

This is the most critical package. It contains all the security rules that meshaudit enforces. Coverage target: ≥ 97%.

#### `mtls_test.go`

Tests the PeerAuthentication resolution engine — the logic that maps each Kubernetes Service to a STRICT, PERMISSIVE, or DISABLED mTLS posture.

**Why it matters:** Istio's policy precedence rules (workload-scoped > namespace-scoped > mesh-wide > default) are subtle and easy to implement incorrectly. A bug here would cause meshaudit to silently misclassify a vulnerable service as secure.

**How it works:**

Tests are split into two groups:

*`TestResolve` — table-driven unit tests of the resolution algorithm*

Each case constructs a set of `PeerAuthentication` objects and one `Service` directly in memory (no API calls, no fake client) and calls `buildPAStore` + `store.resolve` directly. This tests the core algorithm in complete isolation.

Cases covered:

| Test case | What it verifies |
|-----------|-----------------|
| No policy | Defaults to PERMISSIVE (Istio mesh default) |
| Mesh-wide STRICT only | Applies when nothing narrower exists |
| Namespace-scoped overrides mesh-wide | Namespace PERMISSIVE wins over mesh STRICT |
| Workload-scoped overrides namespace-scoped | Workload DISABLE wins over namespace STRICT |
| Workload-scoped overrides mesh-wide | Workload DISABLE wins even without a namespace policy |
| Selector label mismatch | A workload PA with `app: other-svc` does not match `app: payments-svc` |
| Cross-namespace selector | A workload PA in `other-ns` does not affect services in `production` |
| UNSET mode skipped | A PA with `mode: UNSET` is ignored and falls through to the next level |
| Nil Mtls field | A PA with no `mtls` block is treated as UNSET |
| Multi-label selector — partial match | PA requires `app+version`, service only has `app` → no match |
| Multi-label selector — full match | PA requires `app+version`, service has both plus extras → matches |
| All three levels set | Workload DISABLE wins over both namespace STRICT and mesh STRICT |

*`TestScanMTLS` — integration tests through the full `ScanMTLS` function*

These tests use the Istio fake client (`istiofake.NewSimpleClientset`) to pre-populate PeerAuthentication resources, then call the actual `ScanMTLS` function that the `scan` command uses. They verify that:
- An empty cluster returns PERMISSIVE for every service
- A namespace-scoped STRICT policy applies to all services in that namespace
- A workload-scoped DISABLE policy overrides the namespace policy for one service only, while other services in the same namespace keep their namespace-level posture
- An empty service list returns zero findings

The fake client intercepts `List` calls for `PeerAuthentication` resources and returns the pre-populated objects. No real API server is involved.

*Additional tests:*
- `TestScanMTLS_APIError` — injects a reactor that returns an error on any list call, verifies `ScanMTLS` propagates it rather than silently succeeding
- `TestLabelsMatch` — white-box tests of the label subset matching function (empty selector, exact match, subset match, value mismatch, missing key, empty target)
- `TestSuggestedFix` — verifies the plain-English remediation hints are correct for each mode

---

#### `authz_test.go`

Tests the AuthorizationPolicy risk rule engine — the five rules defined in the PRD that flag dangerous policy configurations.

**Why it matters:** A misconfigured AuthorizationPolicy can silently expose services to any caller in the mesh or block all traffic to a namespace. Each rule must fire exactly when its condition is met and never fire when it is not.

**How it works:**

Each test constructs an `AuthorizationPolicy` object directly in memory using the `makeAP` helper and calls `evaluate` (the internal rule engine) directly. This keeps tests fast and fully deterministic.

PRD risk rules and their tests:

**Rule 1 — DENY with no workload selector (`SeverityFail`)**

`TestAuthz_DenyNoSelector_ReturnsFail`: Creates a DENY policy with `selector: nil`. Verifies `evaluate` returns a FAIL finding with the detail message "DENY policy has no workload selector". This is the highest-severity rule because a namespace-wide DENY silently blocks all traffic.

`TestAuthz_DenyWithSelector_NoFail`: Creates a DENY policy *with* a selector. Verifies no FAIL is returned — DENY is only dangerous when it has no scope.

**Rule 2 — No `from` principals (`SeverityWarn`)**

`TestAuthz_NoFromBlock_ReturnsWarn`: Creates an ALLOW policy whose rule has a `To` block but no `From` block at all. Verifies a WARN is returned with "no 'from' principals" in the detail.

**Rule 3 — Wildcard principal `"*"` (`SeverityWarn`)**

`TestAuthz_WildcardPrincipal_ReturnsWarn`: Creates a policy with `principals: ["*"]`. Verifies a WARN is returned with "wildcard principal" in the detail.

**Rule 4 — Wildcard method or path with broad principal scope (`SeverityWarn`)**

`TestAuthz_WildcardMethod_WithWildcardPrincipal_ReturnsWarn`: A rule with `methods: ["*"]` and `principals: ["*"]`. Verifies at least 2 WARNs fire — one for the wildcard principal (Rule 3) and one for the wildcard method+broad principal combination (Rule 4).

`TestAuthz_WildcardPath_WithBroadPrincipal_ReturnsWarn`: A rule with `paths: ["/*"]` and wildcard principal. Verifies "wildcard paths" appears in a WARN detail.

`TestAuthz_WildcardMethod_WithNarrowPrincipal_NoWildcardWarn`: A rule with `methods: ["*"]` but a specific, non-wildcard principal. Verifies Rule 4 does **not** fire — wildcard methods are only dangerous when the caller scope is also broad.

**Rule 5 — Clean policy (`SeverityInfo`)**

`TestAuthz_CleanPolicy_ReturnsInfo`: A policy with an explicit non-wildcard principal and no dangerous patterns. Verifies exactly one INFO finding is returned, confirming the policy was reviewed and found clean.

**Edge cases and robustness tests:**

| Test | What it verifies |
|------|-----------------|
| `TestAuthz_MultipleRulesFireIndependently` | A policy with two rules (one wildcard, one clean) still fires WARN — rules are evaluated individually |
| `TestAuthz_NilSourceInFrom_TreatedAsBroad` | A `Rule_From` with `Source: nil` counts as broad principal scope for Rule 4 purposes |
| `TestAuthz_NilOperation_InTo_IsSkipped` | A `Rule_To` with `Operation: nil` does not panic and is cleanly skipped |
| `TestAuthz_EmptyPrincipals_NonBroad` | A `Source` with an empty `Principals` slice is not treated as a wildcard |
| `TestAuthz_SelectorName_NonAppLabel` | `selectorName` falls back to first label value when no `app` label exists |
| `TestAuthz_SelectorName_EmptyLabels` | `selectorName` returns empty string for empty label maps |
| `TestAuthz_SelectorName_NilPointer_ReturnsEmpty` | `selectorName` handles a nil `*WorkloadSelector` safely via protobuf nil-safe getters |
| `TestRuleHasBroadPrincipals_EmptyFrom` | An empty `From` slice is treated as broad (no caller restriction) |
| `TestScanAuthz_NonForbiddenError_Propagates` | Non-403 API errors are propagated, not swallowed |

*`TestScanAuthz_ViaFakeClient`* is the integration-level test: it calls the full `ScanAuthz` function through the Istio fake client with a pre-populated wildcard policy and verifies a WARN is returned.

---

#### `score_test.go`

Tests the posture score formula and band classification.

**PRD formula:** `Score = 100 − (DISABLED×20) − (PERMISSIVE×10) − (AUTHZ_WARN×5) − (AUTHZ_FAIL×15)`

Each deduction is tested in isolation first:

| Test | Input | Expected score |
|------|-------|----------------|
| `TestScore_AllStrict_Clean_Is100` | 2×STRICT + 1×INFO | 100 / GOOD |
| `TestScore_OneDisabled_Deducts20` | 1×DISABLED | 80 |
| `TestScore_OnePermissive_Deducts10` | 1×PERMISSIVE | 90 |
| `TestScore_AuthzWarn_Deducts5` | 1×AUTHZ_WARN | 95 |
| `TestScore_AuthzFail_Deducts15` | 1×AUTHZ_FAIL | 85 |
| `TestScore_FullFormula` | 2×STRICT + 1×PERMISSIVE + 1×DISABLED + 2×AUTHZ_WARN + 1×AUTHZ_FAIL | 45 / POOR |
| `TestScore_FloorAtZero` | 6×DISABLED (−120) | 0 (not negative) |

`TestScore_BandBoundaries` tests all six band boundary values (100, 90, 89, 70, 69, 0) to verify the GOOD/FAIR/POOR cutoffs are exactly right.

`TestSummary_CountsCorrectly` verifies that STRICT mTLS maps to `pass`, PERMISSIVE maps to `warn`, DISABLED maps to `fail`, INFO authz maps to `pass`, and WARN/FAIL authz map to `warn`/`fail` respectively.

---

### 1.2 `internal/k8s` — Kubernetes resource listing

Tests the functions that fetch namespaces, services, deployments, and VirtualServices from the API server. All tests use `k8s.io/client-go/kubernetes/fake` and `k8s.io/client-go/dynamic/fake` — no real cluster needed.

**Key design: injectable `exitFn`**

`rbacError` normally calls `os.Exit(2)`. Tests override the package-level `exitFn` variable to capture the exit code instead:

```go
func withExitCapture(t *testing.T) *int {
    code := -1
    orig := exitFn
    exitFn = func(c int) { code = c }
    t.Cleanup(func() { exitFn = orig })
    return &code
}
```

This lets tests assert that a 403 Forbidden response from the API triggers `exitFn(2)` without actually terminating the test process.

**What is tested:**

*Namespace listing:*
- All namespaces returned when no scope is specified
- Skip set excludes matching namespaces
- Scoped namespace returns only that namespace
- Scoped namespace that does not exist returns an error
- Forbidden `get` → exits 2 (RBAC error path)
- Forbidden `list` → exits 2
- Generic API error propagates as a normal Go error

*Service listing:*
- Multiple services across multiple namespaces returned correctly
- Service labels are populated from `metadata.labels`
- `PodSelector` is populated from `spec.selector` (the pod label selector, not the service's own labels)
- Empty namespace list returns zero services
- Forbidden list → exits 2
- Generic API error propagates

*Deployment listing:*
- Pod template labels (`spec.template.metadata.labels`) are captured in `PodLabels`, not the deployment's own metadata labels
- Empty namespace returns zero deployments
- Forbidden list → exits 2
- Generic API error propagates

*`EnrichServicesWithDeploymentLabels`:*
- When a deployment in the same namespace has pod labels that are a superset of the service's pod selector, the service's `PodSelector` is updated to the full deployment label set
- No enrichment when no deployment matches the pod selector
- No cross-namespace enrichment (a matching deployment in a different namespace is ignored)

*VirtualService listing (dynamic client):*
- VS name and namespace are correctly extracted from the unstructured object
- `spec` map is populated from the object's `spec` field
- Empty namespace list returns zero VSes
- Multi-namespace queries return VSes from all namespaces

---

### 1.3 `internal/drift` — Drift engine

#### `loader_test.go`

Tests the YAML manifest loader that reads local files and extracts VirtualService objects.

| Test | What it verifies |
|------|-----------------|
| `TestLoadManifests_DirNotFound` | Returns an error when the directory does not exist |
| `TestLoadManifests_EmptyDir` | Returns zero VSes and no error for an empty directory |
| `TestLoadManifests_SkipsNonVS` | A Service YAML in the directory is silently skipped |
| `TestLoadManifests_SingleVS` | A single VS file: name and namespace correctly extracted |
| `TestLoadManifests_MultiDoc` | A single file with two `---`-separated VS documents returns two VSes |
| `TestLoadManifests_NamespaceFilter` | With `namespace="production"`, a staging VS in the same file is excluded |
| `TestLoadManifests_SkipsHiddenDir` | A `.git` directory inside the path is not walked |
| `TestLoadManifests_SkipsNonYAML` | `.md` and `.sh` files are ignored |

Each test uses `t.TempDir()` to create a real temporary directory on disk and writes actual YAML files into it. The loader reads them via `filepath.WalkDir` — this exercises the full file I/O path.

#### `diff_test.go`

Tests the comparison engine that matches live VS resources against desired manifests.

| Test | Setup | Expected status |
|------|-------|----------------|
| `TestCompare_InSync` | Identical spec on both sides | `IN_SYNC`, zero diffs |
| `TestCompare_Drifted` | Live `timeout: 10s`, desired `timeout: 5s` | `DRIFT_DETECTED`, `FieldDiff` on `spec.http` |
| `TestCompare_LiveOnly` | VS in live, no desired | `LIVE_ONLY` |
| `TestCompare_ManifestOnly` | VS in desired, no live | `MANIFEST_ONLY` |
| `TestCompare_MultiNamespace` | Two namespaces — one in-sync, one drifted | Correct status per namespace |
| `TestCompare_SameNameDifferentNamespace` | `reviews-vs` in `production` and `staging` — only production in desired | `IN_SYNC` for production, `LIVE_ONLY` for staging |

The last test verifies the matching key is `namespace/name`, not just `name` — two VSes with the same name in different namespaces are treated as independent resources.

---

### 1.4 `internal/report` — Output renderers

#### `json_test.go`

*`TestBuildReport_Structure`* — verifies `BuildReport` correctly:
- Sets `Cluster` and `Namespace` from arguments
- Counts PASS, WARN, FAIL correctly in `Summary`
- Produces one finding per mTLS finding and one per authz finding
- Sets `type: "mtls"` on mTLS findings and `type: "authz"` on authz findings

*`TestPrintJSON_Roundtrip`* — marshals a `Report` to JSON via `PrintJSON`, unmarshals it back into a `Report` struct, and asserts the cluster name, score, and finding count are preserved exactly.

*`TestBuildReport_RequiredJSONFields`* — marshals a `Report` to JSON and unmarshals into `map[string]interface{}`. Asserts all seven PRD-required top-level keys are present: `cluster`, `scanned_at`, `namespace`, `score`, `score_band`, `summary`, `findings`. This is the acceptance criterion from PRD §8.1 criterion 4.

*`TestMtlsSeverityDetail`* — verifies the mapping from internal `MTLSMode` to JSON severity string: `STRICT → PASS`, `PERMISSIVE → WARN`, `DISABLED → FAIL`, unknown mode → `INFO`.

*`TestPrintDriftJSON_RequiredFields`* — verifies the drift JSON output contains all four required keys: `cluster`, `scanned_at`, `namespace`, `drift_results`.

*`TestPrintDriftJSON_EmptyResults`* — verifies that when drift results are nil, the JSON emits `"drift_results": []` (an empty array) rather than `null`. This matters for consumers that iterate the array.

#### `pretty_test.go`

Tests ANSI terminal output. Since the output contains ANSI escape codes, tests check for the presence of meaningful content strings rather than exact output equality.

| Test | What it verifies |
|------|-----------------|
| `TestPrintHeader_ContainsClusterAndNamespace` | Cluster name and namespace both appear in header |
| `TestPrintMTLS_StrictService` | Service name and "strict" appear in mTLS output |
| `TestPrintMTLS_PermissiveService_IncludesSuggestedFix` | `suggested_fix` text appears for PERMISSIVE services |
| `TestPrintAuthz_FailSeverity` | FAIL detail message appears in authz output |
| `TestPrintSummary_ScoreAndCounts` | Score value appears in summary |
| `TestModeStyle_AllBranches` | All four mTLS mode branches return a non-empty icon, label, and color |
| `TestSeverityStyle_AllBranches` | All three severity branches return a non-empty icon and color |
| `TestScoreColor_Bands` | All three score ranges return a non-nil color |
| `TestPrintDrift_ContainsNameAndStatus` | VS names and field diff keys appear in drift output |
| `TestDriftStyle_AllStatuses` | All five drift status branches return a non-empty icon, label, and color |

---

### 1.5 `cmd` — CLI wiring

#### `scan_test.go`

Tests the thin CLI layer — flag parsing, threshold logic, and exit code decisions — without hitting any API server.

*`TestRunScan_InvalidOutputFormat`* — sets the `output` package variable to `"xml"` and calls `runScan` directly. Verifies it returns an error containing "unknown output format" before attempting any API calls.

*`TestCheckThresholds_MinScore`* — calls `checkThresholds(score=60, minScore=80, ...)` directly. Verifies `errFindings` is returned when the score is below the threshold.

*`TestCheckThresholds_FailOnWarn`* — calls `checkThresholds(score=100, minScore=0, failOnWarn=true, warn=1, ...)`. Verifies `errFindings` is returned when `--fail-on-warn` is set and there is at least one WARN.

*`TestCheckThresholds_Clean`* — verifies `nil` is returned when score is fine, no threshold set, and no findings.

*`TestCheckThresholds_MinScoreZeroDisabled`* — verifies that `minScore=0` never triggers regardless of the actual score. This is a boundary test: `0` is the default value and must be treated as "disabled, not as "fail if score < 0".

---

## Part 2 — Local Functional Tests (`scripts/local-test.sh`)

Run after `./scripts/demo-setup.sh` has provisioned the minikube cluster:

```bash
./scripts/local-test.sh
```

### Why these tests exist separately

The Go tests verify the audit logic using in-memory fakes. They are fast and CI-safe. But they cannot verify that:
- The binary correctly parses kubeconfig and connects to a real API server
- The dynamic client correctly deserializes live VirtualService objects from the Kubernetes API
- The Istio fake client behaves identically to a real `istiod`
- The full command pipeline (cobra → lister → audit → report → stdout) produces correct output

The local test script exercises the compiled binary against real Kubernetes and Istio resources.

### Known fixture state

`demo-setup.sh` creates a deterministic cluster state that the tests assert against:

| Service | PeerAuthentication | Expected mTLS mode | Expected severity |
|---------|-------------------|-------------------|-------------------|
| `payments-svc` | Namespace-scoped STRICT | STRICT | PASS |
| `inventory-svc` | Namespace-scoped STRICT | STRICT | PASS |
| `legacy-api` | Workload-scoped DISABLE (overrides namespace) | DISABLED | FAIL |

No AuthorizationPolicies are deployed, so authz findings = 0.

**Expected score:** `100 − (1 × 20) = 80` → band: `FAIR`

**Expected summary:** `pass=2, warn=0, fail=1`

### What is asserted

**mTLS per-service correctness**
The binary is run with `--output json`. The JSON findings array is parsed with Python and each service's `severity` field is extracted by `service` + `type` and compared to the expected value. This verifies the workload-scoped PA override fired correctly for `legacy-api` and the namespace-scoped policy applied to the other two.

**Score formula**
The actual `score` value from the JSON must be exactly `80` — not "in range", exactly `80`. The `score_band` must be exactly `"FAIR"`.

**Summary counts**
`summary.pass`, `summary.warn`, and `summary.fail` are each asserted to their expected exact values.

**`suggested_fix` populated**
The `legacy-api` finding is checked to have a non-empty `suggested_fix` field.

**Exit code correctness**
The binary is run multiple times with different flags and the exit code is captured:
- No `--fail-on-warn` → `0`
- `--fail-on-warn` → `1` (because `legacy-api` is FAIL)
- `--min-score 50` → `0` (score 80 ≥ 50)
- `--min-score 90` → `1` (score 80 < 90)
- Bad `--output` format → `2`

**Drift — MANIFEST_ONLY**
A VirtualService YAML is written to a temp directory but never applied to the cluster. The drift command is run and the JSON `drift_results` array is checked for a `MANIFEST_ONLY` entry.

**Drift — LIVE_ONLY**
A VirtualService is applied to the cluster with `kubectl apply`. An empty manifest directory is used. The JSON output must contain a `LIVE_ONLY` result for that VS.

**Drift — IN_SYNC**
The same VirtualService spec that was applied to the cluster is written to the manifest directory. The JSON output must contain an `IN_SYNC` result. This verifies that the dynamic client's map representation and the YAML parser's map representation produce identical structures after deep-equal comparison.

**Drift — DRIFT_DETECTED**
The manifest directory is updated with the same VS name but a different `timeout` value (`10s` live vs `5s` in manifest). The JSON output must contain a `DRIFT_DETECTED` result, and the result must have a non-empty `diffs` array. This verifies that `diffSpecs` correctly identifies the changed field.

**Drift exit codes**
- `--fail-on-warn` with drift present → exit `1`
- Missing `--git-path` → exit `2`
- Nonexistent `--git-path` → exit `2`

---

## Running Everything

```bash
# All Go tests
go test -race ./...

# With coverage report
go test -coverprofile=coverage.out ./... && go tool cover -func=coverage.out

# Local functional tests (requires minikube)
./scripts/demo-setup.sh
./scripts/local-test.sh

# Teardown
./scripts/demo-teardown.sh --delete
```
