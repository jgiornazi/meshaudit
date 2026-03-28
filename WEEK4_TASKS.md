# meshaudit — Week 4 Task Plan

**Goal:** Ship v1.1.0 — VirtualService drift detection (`meshaudit drift`), as defined in PRD §4.2 and §5.1.

**Prerequisite:** v1.0.0 must be tagged and released (Week 3 Task 9) before cutting a v1.1.0 release.

**Deliverable:** `meshaudit drift --git-path ./manifests` compares live VirtualService state against local YAML, emits field-level diffs in pretty and JSON output, and exits non-zero on drift when `--fail-on-warn` is set.

---

## Current State Entering Week 4

| Area | Status |
|------|--------|
| v1.0.0 core scan engine | ✅ Complete (shipped in Week 3) |
| `cmd/drift.go` | ❌ Missing |
| `internal/drift/loader.go` | ❌ Missing |
| `internal/drift/diff.go` | ❌ Missing |
| `drift` subcommand registered in `cmd/root.go` | ❌ Missing |
| VirtualService lister in `internal/k8s/` | ❌ Missing |
| Pretty output for drift results | ❌ Missing |
| JSON output for drift results | ❌ Missing |
| Tests for drift engine | ❌ Missing |
| `README.md` drift section | ❌ Missing |
| v1.1.0 GoReleaser tag + release | ❌ Missing |

---

## Tasks

### Task 1 — Add VirtualService lister to `internal/k8s/`
**PRD ref:** §10.1, §10.2
**No dependencies**

The drift engine needs to fetch live VirtualService resources from the cluster. VirtualServices are an Istio CRD (`networking.istio.io/v1beta1`), so they require the dynamic client or the `istio.io/client-go` typed client already in `go.mod`.

**In `internal/k8s/lister.go`**, add:

```go
type VirtualService struct {
    Name        string
    Namespace   string
    Spec        map[string]interface{} // raw spec for field-level diff
    RawManifest []byte                 // JSON-encoded live object
}

func ListVirtualServices(ctx context.Context, dc dynamic.Interface, namespaces []string) ([]VirtualService, error)
```

Use the dynamic client (`k8s.io/client-go/dynamic`) with the GVR:
```go
var vsGVR = schema.GroupVersionResource{
    Group:    "networking.istio.io",
    Version:  "v1beta1",
    Resource: "virtualservices",
}
```

Respect RBAC errors with the same `rbacError` pattern used for services/namespaces.

Update the `meshaudit-reader` RBAC snippet in `rbacError` to include:
```yaml
- apiGroups: ["networking.istio.io"]
  resources: ["virtualservices"]
  verbs: ["get", "list"]
```

Add unit tests in `internal/k8s/lister_test.go` using the existing fake client pattern.

---

### Task 2 — Implement `internal/drift/loader.go`
**PRD ref:** §4.2
**No dependencies**

Loads local Istio YAML manifests from the directory specified by `--git-path`. Returns a slice of `VirtualService` structs (same type as Task 1) populated from disk rather than the API server.

```go
package drift

// LoadManifests walks dir recursively, parses any YAML/JSON files, and returns
// all objects whose apiVersion is "networking.istio.io/v1beta1" and kind is
// "VirtualService". Non-VS objects are silently skipped.
func LoadManifests(dir string) ([]k8s.VirtualService, error)
```

Requirements:
- Walk the directory tree with `filepath.WalkDir`; skip hidden directories (`.git`, `.github`)
- Support both `.yaml` and `.yml` extensions
- A single file may contain multiple documents separated by `---`
- Unmarshal each document via `sigs.k8s.io/yaml` (already a transitive dep via `k8s.io/apimachinery`) into `map[string]interface{}` for field-level comparison
- Return a clear error if `dir` does not exist or is not readable
- If `--namespace` is set, filter loaded manifests to that namespace only (match on `metadata.namespace`)

Unit tests in `internal/drift/loader_test.go`:
- `TestLoadManifests_EmptyDir`: returns empty slice, no error
- `TestLoadManifests_SkipsNonVS`: YAML with a Service object is skipped
- `TestLoadManifests_MultiDoc`: file with two VS documents returns two entries
- `TestLoadManifests_DirNotFound`: returns error when path does not exist

---

### Task 3 — Implement `internal/drift/diff.go`
**PRD ref:** §4.2
**Depends on Tasks 1 and 2**

Core diff engine. Compares live VirtualService state (from cluster) against desired state (from local YAML).

```go
package drift

type DriftStatus string

const (
    StatusInSync       DriftStatus = "IN_SYNC"
    StatusDrifted      DriftStatus = "DRIFT_DETECTED"
    StatusLiveOnly     DriftStatus = "LIVE_ONLY"    // exists in cluster, not in git
    StatusManifestOnly DriftStatus = "MANIFEST_ONLY" // exists in git, not in cluster
)

type FieldDiff struct {
    Field    string      `json:"field"`
    Live     interface{} `json:"live"`
    Desired  interface{} `json:"desired"`
}

type VSResult struct {
    Name      string      `json:"name"`
    Namespace string      `json:"namespace"`
    Status    DriftStatus `json:"status"`
    Diffs     []FieldDiff `json:"diffs,omitempty"`
}

// Compare matches live VS resources against desired manifests by namespace+name.
// Returns one VSResult per unique VS seen in either source.
func Compare(live, desired []k8s.VirtualService) []VSResult
```

Field-level diff scope (PRD §4.2): host routing rules, weights, retries, timeouts, fault injection. These all live under `spec.http`, `spec.tcp`, and `spec.tls` in the VS spec. Diff at the top level of each array element (no recursive deep-equal beyond one level — flag any spec difference as a drift, report the full spec value for live vs desired).

Matching logic:
- Match on `namespace + name`
- If a VS is in live but not desired → `LIVE_ONLY`
- If a VS is in desired but not live → `MANIFEST_ONLY`
- If both present: deep-equal `spec` — equal → `IN_SYNC`, not equal → `DRIFT_DETECTED` with `FieldDiff` entries for each top-level spec key that differs

Unit tests in `internal/drift/diff_test.go`:
- `TestCompare_InSync`: identical live and desired → `IN_SYNC`
- `TestCompare_Drifted`: spec differs → `DRIFT_DETECTED` with correct FieldDiffs
- `TestCompare_LiveOnly`: VS in live, not desired → `LIVE_ONLY`
- `TestCompare_ManifestOnly`: VS in desired, not live → `MANIFEST_ONLY`
- `TestCompare_MultiNamespace`: two namespaces, each with one match and one drift

---

### Task 4 — Implement `cmd/drift.go`
**PRD ref:** §5.1
**Depends on Tasks 1, 2, 3**

Register the `drift` subcommand under the root Cobra command.

```
meshaudit drift --git-path ./manifests [--namespace ns] [--output json] [--fail-on-warn]
```

Flags (in addition to inherited global flags):
- `--git-path string` — path to local directory of Istio YAML manifests (required)

Execution flow:
1. Validate `--git-path` is set and the directory exists; exit 2 if not
2. Build k8s client from kubeconfig (same as `scan`)
3. Determine namespace scope from `--namespace` (or all namespaces)
4. Call `k8s.ListVirtualServices` to fetch live state
5. Call `drift.LoadManifests` to load desired state
6. Call `drift.Compare` to produce `[]VSResult`
7. Render output:
   - Pretty: call `report.PrintDrift` (Task 5)
   - JSON: call `report.PrintDriftJSON` (Task 5)
8. Exit code:
   - `0` — all results `IN_SYNC` (or `--fail-on-warn` not set)
   - `1` — any `DRIFT_DETECTED`, `LIVE_ONLY`, or `MANIFEST_ONLY` and `--fail-on-warn` is set
   - `2` — error (bad git-path, cluster unreachable, etc.)

Register in `cmd/root.go`:
```go
rootCmd.AddCommand(newDriftCmd())
```

---

### Task 5 — Add drift output renderers to `internal/report/`
**PRD ref:** §4.2
**Depends on Task 3**

#### Pretty terminal (`internal/report/pretty.go`)

Add `PrintDrift(w io.Writer, results []drift.VSResult)`:

```
VirtualService Drift
✅  reviews-vs        production    IN SYNC
⚠️  ratings-vs        production    DRIFT DETECTED
    └─ spec.http[0].retries.attempts: live=3, desired=5
    └─ spec.http[0].timeout: live="10s", desired="5s"
❌  old-vs            production    LIVE ONLY (not in git)
📋  new-feature-vs    staging       MANIFEST ONLY (not deployed)
```

Use the same color/icon convention as the scan output:
- `✅` / green → `IN_SYNC`
- `⚠️` / yellow → `DRIFT_DETECTED` or `MANIFEST_ONLY`
- `❌` / red → `LIVE_ONLY`

#### JSON (`internal/report/json.go`)

Add `PrintDriftJSON(w io.Writer, cluster string, scannedAt time.Time, namespace string, results []drift.VSResult) error`.

Schema:
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
        { "field": "spec.http", "live": {...}, "desired": {...} }
      ]
    }
  ]
}
```

Add tests in `internal/report/pretty_test.go` and `internal/report/json_test.go` for the new drift renderers.

---

### Task 6 — Update CI for drift coverage
**PRD ref:** §8.2 quality targets
**Depends on Tasks 1–5**

The existing CI coverage gate is 75% total. With the new drift package, coverage must be maintained. No structural changes to CI are needed — the existing `go test -race -coverprofile=coverage.out ./...` will pick up the new packages automatically.

Verify locally that `go test ./internal/drift/... -v` covers:
- `loader.go` ≥ 80%
- `diff.go` ≥ 80%

If the gate drops below 75% total, add tests to bring it back before merging.

Also add a CI lint check for the new `drift` package — no `golangci-lint` exclusions should be needed if the code follows existing patterns.

---

### Task 7 — Update `README.md` with drift section
**PRD ref:** §4.2, §5.1
**Depends on Tasks 4 and 5**

Add a new **Drift Detection (v1.1)** section to `README.md` after the existing scan documentation:

Contents:
1. One-paragraph description of the feature and use case (GitOps drift detection)
2. Usage example:
   ```bash
   meshaudit drift --git-path ./manifests
   meshaudit drift --git-path ./manifests --namespace production --output json | jq .drift_results
   meshaudit drift --git-path ./manifests --fail-on-warn  # CI gate
   ```
3. Output example (pretty terminal with DRIFT DETECTED and field diffs)
4. JSON schema sample matching Task 5
5. Note on scope: VirtualService only; no mutation
6. Updated RBAC section: add `virtualservices` rule to the `meshaudit-reader` ClusterRole

---

### Task 8 — Tag v1.1.0 and release
**PRD ref:** §7 (v1.1 sprint)
**Depends on all prior tasks**

Pre-release checklist:
- [ ] All CI jobs green on `main`
- [ ] `go test -race ./...` passes
- [ ] `golangci-lint run ./...` zero high-severity findings
- [ ] Binary size still < 20 MB (`darwin/arm64`)
- [ ] `goreleaser check` passes
- [ ] Manual smoke test: `meshaudit drift --git-path ./testdata/manifests` against minikube
- [ ] `README.md` drift section verified on a clean machine

Then:
```bash
git tag v1.1.0
git push origin v1.1.0
```

GoReleaser publishes artifacts and updates the Homebrew formula automatically.

Post-release smoke test:
```bash
brew update && brew upgrade meshaudit
meshaudit version   # should print v1.1.0
meshaudit drift --help
```

---

## Dependency Graph

```
Task 1  (VS lister in k8s/)               — no deps
Task 2  (drift/loader.go)                  — no deps
Task 3  (drift/diff.go)                    — depends on Tasks 1, 2
Task 4  (cmd/drift.go)                     — depends on Tasks 1, 2, 3
Task 5  (report: drift renderers)          — depends on Task 3
Task 6  (CI coverage validation)           — depends on Tasks 1–5
Task 7  (README drift section)             — depends on Tasks 4, 5
Task 8  (v1.1.0 tag + release)            — depends on all prior tasks
```

Tasks 1 and 2 can be worked in parallel. Task 3 waits on both. Tasks 4 and 5 can be worked in parallel once Task 3 is done. Task 6 is continuous validation. Task 7 follows Tasks 4 and 5. Task 8 is the final gate.

---

## PRD Acceptance Criteria — v1.1

| # | Criterion | Task | Status |
|---|-----------|------|--------|
| 1 | `drift` accepts `--git-path` and `--namespace` flags | Task 4 | ⬜ |
| 2 | Diffs host routing rules, weights, retries, timeouts, fault injection | Task 3 | ⬜ |
| 3 | Emits `DRIFT DETECTED` or `IN SYNC` per VirtualService | Tasks 3, 5 | ⬜ |
| 4 | `--output json` emits structured diff object | Task 5 | ⬜ |
| 5 | `--fail-on-warn` exits 1 on any drift | Task 4 | ⬜ |
| 6 | Read-only — no cluster mutation | Task 4 (design constraint) | ⬜ |
| 7 | Installs v1.1.0 via Homebrew | Task 8 | ⬜ |

---

## Out of Scope for v1.1

Per PRD §3.2 and §4.2 scope boundaries:

- No Envoy / non-Istio mesh support
- No DestinationRule or Gateway drift detection (future roadmap)
- No automatic remediation — drift is reported only, never fixed
- No server-side component or persistent state
