# meshaudit — Week 3 Task Plan

**Goal:** Ship v1.0.0. Release pipeline, distribution, documentation, and final quality gate — as defined in the PRD §7 Week 3 sprint.

**Deliverable:** `meshaudit v1.0.0` publicly released, installable via `brew install meshaudit`, tested end-to-end.

---

## Current State

| Area | Status |
|------|--------|
| mTLS scanner (Weeks 1–2) | ✅ Complete |
| AuthorizationPolicy auditor (Week 2) | ✅ Complete |
| Posture score + banding (Week 2) | ✅ Complete |
| Pretty + JSON output (Week 2) | ✅ Complete |
| `--fail-on-warn`, `--min-score`, exit codes (Week 2) | ✅ Complete |
| CI: go test, go vet, golangci-lint (Week 2) | ✅ Complete |
| Test coverage: 75% total / 97.9% internal/audit (pre-Week 3 fixes) | ✅ Complete |
| Makefile: build, test, lint, clean | ✅ Complete |
| `version` subcommand + `-ldflags` injection | ✅ Complete |
| `.goreleaser.yaml` | ❌ Missing |
| `README.md` | ❌ Missing |
| `CONTRIBUTING.md` + issue templates | ❌ Missing |
| GitHub Release notes template | ❌ Missing |
| Homebrew tap formula | ❌ Missing |
| CI: `jq` validation of `--output json` | ❌ Missing |
| CI: binary size gate (< 20 MB) | ❌ Missing |
| Deployment label resolution (PRD §10.1) | ❌ Missing |
| Demo GIF | ❌ Missing |

---

## Tasks

### Task 1 — Add `.goreleaser.yaml`
**PRD ref:** §7 Week 3, §6.3
**No dependencies**

Create the GoReleaser configuration at the repo root. Must produce:
- Binaries for `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`
- SHA-256 checksums file (`checksums.txt`)
- Injects the git tag into `cmd.Version` via `-ldflags`
- Archives named `meshaudit_<version>_<os>_<arch>.tar.gz`

```yaml
# .goreleaser.yaml (skeleton — expand as needed)
project_name: meshaudit
builds:
  - id: meshaudit
    main: .
    binary: meshaudit
    ldflags:
      - -s -w -X github.com/jgiornazi/meshaudit/cmd.Version={{.Version}}
    goos: [linux, darwin]
    goarch: [amd64, arm64]
archives:
  - format: tar.gz
    name_template: "{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}"
checksum:
  name_template: "checksums.txt"
  algorithm: sha256
brews:
  - repository:
      owner: jgiornazi
      name: homebrew-meshaudit
    homepage: https://github.com/jgiornazi/meshaudit
    description: "Istio mTLS & AuthorizationPolicy security auditor for Kubernetes"
    license: MIT
    install: bin.install "meshaudit"
    test: |
      system "#{bin}/meshaudit version"
```

Also update `Makefile` to add a `release` target:
```makefile
release:
	goreleaser release --clean
```

---

### Task 2 — Add GitHub Release notes template
**PRD ref:** §7 Week 3
**No dependencies**

Create `.github/release-notes.md` (used by GoReleaser's `release.footer`/`changelog`) to give each release a consistent structure.

```markdown
## Install

**Homebrew (macOS / Linux)**
\`\`\`
brew tap jgiornazi/meshaudit
brew install meshaudit
\`\`\`

**Direct download**
See assets below for pre-built binaries. Verify with `checksums.txt`.

## Changelog
{{ .Changelog }}
```

Add to `.goreleaser.yaml`:
```yaml
changelog:
  sort: asc
  filters:
    exclude:
      - "^docs:"
      - "^test:"
      - "^chore:"
release:
  footer: |
    **Full Changelog**: https://github.com/jgiornazi/meshaudit/compare/{{ .PreviousTag }}...{{ .Tag }}
```

---

### Task 3 — Add CI job: `--output json` validation
**PRD ref:** §8.1 criterion #4
**No dependencies**

The PRD acceptance criteria require that `--output json` emits valid JSON parseable by `jq` with all required fields. Since we can't hit a real cluster in CI, validate the JSON schema via a unit test that calls `report.BuildReport` + `report.PrintJSON` and asserts all top-level fields are present.

Add to `internal/report/json_test.go`:

- `TestBuildReport_RequiredJSONFields`: marshal a `Report` to JSON, unmarshal into `map[string]interface{}`, assert keys `cluster`, `scanned_at`, `namespace`, `score`, `score_band`, `summary`, `findings` are all present.

---

### Task 4 — Add CI job: binary size gate
**PRD ref:** §8.1 criterion #7 (< 20 MB)
**Depends on Task 1**

Add a step to the CI `test` job that builds the binary with the release ldflags and checks its size:

```yaml
- name: Binary size gate (< 20 MB)
  run: |
    go build -ldflags "-s -w -X github.com/jgiornazi/meshaudit/cmd.Version=ci" -o meshaudit_ci .
    SIZE=$(du -k meshaudit_ci | awk '{print $1}')
    echo "Binary size: ${SIZE} KB"
    awk -v s="$SIZE" 'BEGIN { if (s+0 > 20480) { print "FAIL: binary " s "KB exceeds 20MB limit"; exit 1 } }'
    rm meshaudit_ci
```

---

### Task 5 — Implement Deployment label resolution
**PRD ref:** §10.1 Istio Resource Reference, §10.2 RBAC Requirements
**No dependencies**

The PRD's RBAC spec and resource reference both list `apps/v1 Deployments` as a required read. Currently `ScanMTLS` matches workload-scoped PeerAuthentication selectors against **Service labels**. Istio PA selectors target **pod labels** (set on the Deployment's pod template), which can differ from Service labels.

**In `internal/k8s/lister.go`:**

Add a `Deployment` struct and `ListDeployments` function mirroring the existing `ListServices` pattern:

```go
type Deployment struct {
    Name      string
    Namespace string
    Labels    map[string]string // pod template labels (spec.template.metadata.labels)
}

func ListDeployments(ctx context.Context, kube kubernetes.Interface, namespaces []string) ([]Deployment, error)
```

**In `cmd/scan.go`:**

Call `meshk8s.ListDeployments` alongside services and pass both into a helper that correlates each `Service` with its backing `Deployment`'s pod labels (match on `app` label or namespace+name). Fall back to Service labels when no matching Deployment is found — preserving existing behaviour.

**Note:** This is the last missing piece from the PRD's resource reference before v1.0 tag. The `meshaudit-reader` ClusterRole in `README.md` (Task 6) must include the `deployments` rule.

---

### Task 6 — Write `README.md`
**PRD ref:** §7 Week 3, §8.2 quality targets
**Soft dependency on Tasks 1 and 5** (install instructions need release artifacts; RBAC section needs Deployment rule)

The PRD states the README must cover: install instructions, all flags, output examples, and CI integration. The quality target requires it to be verified by a dry-run on a clean machine before tagging.

Sections to include:

1. **Overview** — one-paragraph description matching PRD §1
2. **Install**
   - Homebrew: `brew tap jgiornazi/meshaudit && brew install meshaudit`
   - Direct download from GitHub Releases (with checksum verification)
   - Build from source: `go install github.com/jgiornazi/meshaudit@latest`
3. **Quick Start** — `meshaudit scan` and `meshaudit scan --namespace production`
4. **Commands & Flags** — full table from PRD §5.1 (global flags, scan flags, exit codes from §5.2)
5. **Output Examples**
   - Pretty terminal output (copy from PRD §4.1.5)
   - JSON output (`--output json`) with sample matching PRD §10.3
6. **CI Integration** — GitHub Actions example using `--fail-on-warn` and `--min-score`
7. **Required RBAC** — `ClusterRole` manifest from PRD §10.2 (with `deployments` rule added per Task 5)
8. **Scoring** — formula and bands from PRD §4.1.4
9. **Limitations** — Non-goals from PRD §3.2 (no mutation, no Helm, v1 only covers mTLS + AuthzPolicy)
10. **Contributing** — link to `CONTRIBUTING.md`
11. **License** — MIT

---

### Task 7 — Write `CONTRIBUTING.md` and GitHub issue templates
**PRD ref:** §7 Week 3
**No dependencies**

**`CONTRIBUTING.md`** should cover:
- Prerequisites (Go 1.22+, a kubeconfig, golangci-lint)
- `make build` / `make test` / `make lint` workflow
- Branch naming and PR expectations
- Where risk rules live (`internal/audit/`) and how to add a new one
- How to run the authz + mTLS tests in isolation

**`.github/ISSUE_TEMPLATE/bug_report.md`:**
```markdown
---
name: Bug report
about: Something meshaudit does incorrectly or unexpectedly
---
**meshaudit version** (`meshaudit version`):
**Kubernetes version** (`kubectl version`):
**Istio version**:
**Command run**:
**Expected behaviour**:
**Actual behaviour**:
**Relevant output** (redact sensitive data):
```

**`.github/ISSUE_TEMPLATE/feature_request.md`:**
```markdown
---
name: Feature request
about: Suggest a new check, flag, or output format
---
**Problem this solves**:
**Proposed solution**:
**Alternatives considered**:
**Is this in scope for v1.x?** (see README Limitations):
```

---

### Task 8 — Record demo GIF
**PRD ref:** §7 Week 3
**Depends on Task 5 (complete feature set), Task 6 (README ready to reference GIF)**

Record a ≤ 90-second terminal screencast using [vhs](https://github.com/charmbracelet/vhs) or `ttyrec`/`asciinema` against a local minikube cluster with:
1. `meshaudit scan` — full cluster output, POOR score
2. `meshaudit scan --namespace production --output json | jq .score`
3. `meshaudit scan --fail-on-warn` — exits 1

Output: `docs/demo.gif`. Add to README.md hero section.

Minikube setup script for the demo (to keep it reproducible):
- 1 namespace `production` with 2 services (one STRICT, one PERMISSIVE)
- 1 AuthorizationPolicy with a wildcard principal
- Score should land in POOR band (< 70) for visual impact

---

### Task 9 — Tag v1.0.0 and smoke-test
**PRD ref:** §7 Week 3
**Depends on all prior tasks**

Final release checklist before tagging:

- [ ] All CI jobs green on `main`
- [ ] `go vet ./...` clean locally
- [ ] `golangci-lint run ./...` zero high-severity findings
- [ ] `go test -race ./...` passes
- [ ] Binary size < 20 MB (`darwin/arm64` is usually the largest)
- [ ] `README.md` dry-run on a clean machine (no prior meshaudit install)
- [ ] `.goreleaser.yaml` validated: `goreleaser check`
- [ ] Homebrew formula renders correctly: `goreleaser release --snapshot --clean`

Then:
```bash
git tag v1.0.0
git push origin v1.0.0
```

GoReleaser GitHub Actions workflow publishes artifacts and pushes the Homebrew formula. Post-release smoke test:
```bash
brew tap jgiornazi/meshaudit
brew install meshaudit
meshaudit version   # should print v1.0.0
meshaudit scan --help
```

---

## Dependency Graph

```
Task 1  (.goreleaser.yaml + Makefile release target)   — no deps
Task 2  (release notes template)                       — no deps
Task 3  (CI: JSON fields test)                         — no deps
Task 4  (CI: binary size gate)                         — depends on Task 1
Task 5  (Deployment label resolution)                  — no deps
Task 6  (README.md)                                    — soft dep on Tasks 1, 5
Task 7  (CONTRIBUTING.md + issue templates)            — no deps
Task 8  (demo GIF)                                     — depends on Tasks 5, 6
Task 9  (v1.0.0 tag + smoke-test)                      — depends on all prior tasks
```

Tasks 1, 2, 3, 5, and 7 can be worked in parallel. Task 4 waits on Task 1. Task 6 can start in parallel but should be finalized after Tasks 1 and 5 land. Task 8 is last before the tag. Task 9 is the final gate.

---

## PRD Acceptance Criteria Tracker

| # | Criterion | Task | Status |
|---|-----------|------|--------|
| 1 | Scan completes < 30s on 100-service cluster | — (benchmark manually pre-tag) | ⬜ |
| 2 | mTLS precedence resolves correctly (all 3 levels) | ✅ Done (Week 1–2 tests) | ✅ |
| 3 | All 5 AuthzPolicy risk rules fire on crafted fixtures | ✅ Done (Week 2 tests) | ✅ |
| 4 | `--output json` emits valid JSON parseable by `jq` | Task 3 | ⬜ |
| 5 | `--fail-on-warn` exits 1 / 0 correctly | ✅ Done (Week 2 + pre-W3 fix) | ✅ |
| 6 | Installs via `brew install meshaudit` on macOS | Task 9 | ⬜ |
| 7 | Binary < 20 MB on all platforms | Task 4 | ⬜ |

---

## v1.1 Note

Per PRD §4.2, **VirtualService drift detection** (`meshaudit drift --git-path ./manifests`) is scoped to v1.1 — estimated one additional week. The `internal/drift/` package (`loader.go`, `diff.go`) and `cmd/drift.go` are **not** part of this sprint. Do not stub them out; v1.1 will add them cleanly.
