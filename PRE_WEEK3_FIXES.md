# meshaudit — Pre-Week 3 Fix Plan

**Goal:** Address all quality issues identified in the Week 1–2 review before starting Week 3 work.

---

## Issues Summary

| # | Issue | Severity |
|---|-------|----------|
| 1 | Zero test coverage on `internal/k8s`, `internal/report`, `cmd` | High |
| 2 | `--output` flag accepts invalid values silently | Medium |
| 3 | `selectorName()` non-deterministic map iteration | Medium |
| 4 | `fatih/color` marked as `// indirect` in `go.mod` | Low |
| 5 | `contains()` in test file reimplements `strings.Contains` | Low |
| 6 | CI coverage gate uses function-average, not statement coverage | Medium |
| 7 | `os.Exit(1)` called directly in command handler (untestable) | Medium |

---

## Tasks

### Task 1 — Clean up `contains()` in `authz_test.go`
**Issue:** #5
**File:** `internal/audit/authz_test.go`
**No dependencies**

Remove the 10-line manual `contains()` function. Replace all call sites with `strings.Contains`. Add `"strings"` to the import block.

- Delete the `contains()` function (lines 71–81)
- In `hasDetail`: change `contains(f.Detail, substr)` → `strings.Contains(f.Detail, substr)`
- Replace the two remaining direct `contains()` calls in `TestAuthz_WildcardMethod_WithNarrowPrincipal_NoWildcardWarn` and `TestAuthz_EmptyPrincipals_NonBroad`

---

### Task 2 — Fix `fatih/color` in `go.mod`
**Issue:** #4
**File:** `go.mod`
**No dependencies**

`fatih/color` is directly imported in `internal/report/pretty.go` but listed as `// indirect` in `go.mod`. Run `go mod tidy` to promote it to a direct dependency.

```bash
go mod tidy
```

---

### Task 3 — Fix `selectorName()` non-deterministic map iteration
**Issue:** #3
**File:** `internal/audit/authz.go`
**No dependencies**

The fallback for non-`app` labels iterates a Go map — iteration order is randomised per run. Replace with a sorted-key approach so output is deterministic.

```go
// Replace the current fallback:
keys := make([]string, 0, len(labels))
for k := range labels {
    keys = append(keys, k)
}
sort.Strings(keys)
if len(keys) > 0 {
    return labels[keys[0]]
}
return ""
```

Add `"sort"` to the import block in `authz.go`.

---

### Task 4 — Validate `--output` flag value
**Issue:** #2
**File:** `cmd/scan.go`
**No dependencies**

`--output xml` silently falls through to the pretty renderer. Add a validation guard at the top of `runScan`, before any API calls:

```go
switch output {
case "pretty", "json":
    // valid
default:
    return fmt.Errorf("unknown output format %q: must be \"pretty\" or \"json\"", output)
}
```

---

### Task 5 — Replace `os.Exit(1)` with a sentinel error
**Issue:** #7
**Files:** `cmd/scan.go`, `cmd/root.go`
**No dependencies — but must land before Task 6**

`os.Exit(1)` called directly inside `runScan` bypasses Cobra error handling and is untestable. Replace with a sentinel error.

**In `cmd/scan.go`:**

Declare a package-level sentinel:
```go
var errFindings = errors.New("findings exceed threshold")
```

Extract the two threshold checks into a testable helper:
```go
func checkThresholds(score, minScore int, failOnWarn bool, warn, fail int) error {
    if minScore > 0 && score < minScore {
        return errFindings
    }
    if failOnWarn && (warn > 0 || fail > 0) {
        return errFindings
    }
    return nil
}
```

Replace the `os.Exit(1)` calls in `runScan` with:
```go
return checkThresholds(result.Score, minScore, failOnWarn, warn, fail)
```

**In `cmd/root.go`:**

Update `Execute()` to map the sentinel to exit code 1:
```go
func Execute() {
    if err := rootCmd.Execute(); err != nil {
        if errors.Is(err, errFindings) {
            os.Exit(1)
        }
        os.Exit(2)
    }
}
```

Add `"errors"` to imports in both files.

---

### Task 6 — Add `cmd` tests
**Issue:** #1 (cmd)
**New file:** `cmd/scan_test.go`
**Depends on Tasks 4 and 5**

Tests for the logic that is now testable after Tasks 4 and 5.

- `TestRunScan_InvalidOutputFormat`: set `output = "xml"`, call `runScan(nil, nil)`, expect error containing `"unknown output format"`
- `TestCheckThresholds_MinScore`: score below threshold returns `errFindings`
- `TestCheckThresholds_FailOnWarn`: `warn=1`, `failOnWarn=true` returns `errFindings`
- `TestCheckThresholds_Clean`: score=100, minScore=0, failOnWarn=false, warn=0, fail=0 returns nil
- `TestCheckThresholds_MinScoreZeroDisabled`: `minScore=0` never triggers regardless of score

---

### Task 7 — Add `internal/k8s/lister_test.go`
**Issue:** #1 (k8s)
**New file:** `internal/k8s/lister_test.go`
**No dependencies**

Use `k8sfake.NewSimpleClientset(...)` — no real cluster needed.

- `TestParseSkipSet`: table-driven — empty string, single value, multiple values, whitespace trimming
- `TestListNamespaces_AllNamespaces`: two namespaces in fake client, both returned
- `TestListNamespaces_SkipSet`: one namespace in skip set, only the other returned
- `TestListNamespaces_ScopedNamespace`: scoped to `"production"`, only that namespace returned
- `TestListNamespaces_ScopedNamespace_NotFound`: no matching namespace, expect not-found error
- `TestListServices_MultiNamespace`: services across two namespaces, all returned with correct labels
- `TestListServices_EmptyNamespaceList`: empty slice in, empty slice out, no error

> Note: `rbacError()` calls `os.Exit(2)` and is not testable without further refactoring. Skip those branches.

---

### Task 8 — Add `internal/report/json_test.go`
**Issue:** #1 (report/json)
**New file:** `internal/report/json_test.go`
**No dependencies**

- `TestBuildReport_Structure`: known mix of mTLS and authz findings — assert `Cluster`, `Namespace`, `Score`, `Summary.Pass/Warn/Fail`, finding count, and type/severity field values
- `TestPrintJSON_Roundtrip`: call `PrintJSON` into a `bytes.Buffer`, unmarshal back to `Report`, assert field equality
- `TestMtlsSeverityDetail`: table-driven for all three mTLS modes plus the default branch

---

### Task 9 — Add `internal/report/pretty_test.go`
**Issue:** #1 (report/pretty)
**New file:** `internal/report/pretty_test.go`
**Soft dependency on Task 3** (deterministic names in output)

Write to `bytes.Buffer` — not a TTY, so `fatih/color` suppresses ANSI codes and output is predictable.

- `TestPrintHeader_ContainsClusterAndNamespace`: assert cluster name and namespace appear in output
- `TestPrintMTLS_StrictService`: assert service name and `"strict"` appear
- `TestPrintMTLS_PermissiveService_IncludesSuggestedFix`: assert suggested fix text appears
- `TestPrintAuthz_FailSeverity`: assert `f.Detail` appears in output
- `TestPrintSummary_ScoreAndCounts`: known findings producing score 80, assert `"80"` in output
- `TestModeStyle_AllBranches`: table-driven for Strict, Permissive, Disabled, default
- `TestSeverityStyle_AllBranches`: table-driven for Fail, Warn, Info
- `TestScoreColor_Bands`: call with 95, 75, 50 — assert non-nil, no panic

---

### Task 10 — Fix CI coverage gate
**Issue:** #6
**File:** `.github/workflows/ci.yml`
**Depends on Tasks 6, 7, 8, 9**

The current gate averages per-function coverage percentages — a weak signal. Replace with total statement coverage using the `total:` line from `go tool cover -func`.

Replace the current coverage step with:
```yaml
- name: Coverage gate (≥ 75% total statement coverage)
  run: |
    COVERAGE=$(go tool cover -func=coverage.out \
      | grep '^total:' \
      | awk '{print $3}' \
      | sed 's/%//')
    echo "Total statement coverage: ${COVERAGE}%"
    awk -v c="$COVERAGE" 'BEGIN {
      if (c+0 < 75) {
        print "FAIL: coverage " c "% is below 75% threshold"
        exit 1
      }
    }'
```

> Tune the threshold after running the new tests once to confirm the actual total. 75% is a safe starting point given the new test files added in Tasks 6–9.

---

## Dependency Graph

```
Task 1  (authz_test contains())     — no deps
Task 2  (go mod tidy)               — no deps
Task 3  (selectorName sort)         — no deps
Task 4  (output validation)         — no deps
Task 5  (os.Exit → sentinel)        — no deps  ← must land before Task 6
Task 6  (cmd tests)                 — depends on Tasks 4, 5
Task 7  (k8s/lister tests)          — no deps
Task 8  (report/json tests)         — no deps
Task 9  (report/pretty tests)       — soft dep on Task 3
Task 10 (CI coverage gate)          — depends on Tasks 6, 7, 8, 9
```

Tasks 1–4, 7, and 8 can be worked in parallel. Task 5 must land before Task 6. Task 10 is last.
