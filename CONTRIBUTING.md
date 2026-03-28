# Contributing to meshaudit

Thank you for your interest in contributing. meshaudit is a focused security auditing tool — contributions that sharpen its accuracy, coverage, or usability are welcome.

---

## Prerequisites

- **Go 1.22+** — `go version`
- **golangci-lint** — `brew install golangci-lint` or see [golangci-lint install docs](https://golangci-lint.run/usage/install/)
- **A kubeconfig** — for manual smoke testing against a real or local cluster (minikube, kind)

---

## Development Workflow

```bash
# Clone
git clone https://github.com/jgiornazi/meshaudit.git
cd meshaudit

# Build
make build

# Run all tests
make test

# Run tests with race detector (required before submitting a PR)
go test -race ./...

# Lint
make lint

# Build with version injection (mirrors release build)
make build VERSION=dev-local
```

---

## Project Structure

```
meshaudit/
├── cmd/
│   ├── root.go          # Global flags, kubeconfig init, Cobra root
│   ├── scan.go          # scan subcommand
│   ├── drift.go         # drift subcommand (v1.1)
│   └── version.go       # version subcommand
├── internal/
│   ├── audit/
│   │   ├── mtls.go      # PeerAuthentication resolution logic
│   │   ├── authz.go     # AuthorizationPolicy risk rules
│   │   └── score.go     # Posture score calculation
│   ├── drift/
│   │   ├── loader.go    # Load local YAML manifests (v1.1)
│   │   └── diff.go      # Diff live vs desired VirtualService state (v1.1)
│   ├── k8s/
│   │   ├── client.go    # kubeconfig + client-go init
│   │   └── lister.go    # Namespace, Service, Deployment, VirtualService listers
│   └── report/
│       ├── pretty.go    # Terminal renderer (ANSI color + icons)
│       └── json.go      # JSON marshaller
```

---

## Adding a New Audit Rule

All mTLS rules live in `internal/audit/mtls.go`. All AuthorizationPolicy rules live in `internal/audit/authz.go`.

**To add a new AuthzPolicy rule:**

1. Open `internal/audit/authz.go` and locate the `ScanAuthz` function.
2. Add your rule check inside the loop that iterates over policies or their rules.
3. Append an `AuthzFinding` with the appropriate `Severity` (`SeverityWarn` or `SeverityFail`), a `Detail` message, and a `SuggestedFix`.
4. Add a table-driven test case in `internal/audit/authz_test.go` with a crafted fixture that triggers the rule.
5. Verify coverage: `go test -coverprofile=coverage.out ./internal/audit/... && go tool cover -func=coverage.out`

**To add a new mTLS rule:**

Follow the same pattern in `internal/audit/mtls.go` / `internal/audit/mtls_test.go`.

---

## Running Tests in Isolation

```bash
# mTLS rule tests only
go test ./internal/audit/ -run TestMTLS -v

# AuthzPolicy rule tests only
go test ./internal/audit/ -run TestAuthz -v

# k8s lister tests only
go test ./internal/k8s/ -v

# Report tests only
go test ./internal/report/ -v

# Drift tests only (v1.1)
go test ./internal/drift/ -v
```

---

## Branch Naming

| Type | Pattern | Example |
|------|---------|---------|
| Feature | `feat/<short-description>` | `feat/deny-no-selector-rule` |
| Bug fix | `fix/<short-description>` | `fix/namespace-scope-resolution` |
| Docs | `docs/<short-description>` | `docs/ci-integration-guide` |
| Chore | `chore/<short-description>` | `chore/update-golangci-lint` |

---

## Pull Request Expectations

- All CI jobs must pass (`go test`, `go vet`, `golangci-lint`)
- New rules must have corresponding test coverage
- `go test -race ./...` must pass cleanly
- Keep PRs focused — one rule or fix per PR where possible
- No new external dependencies without discussion in an issue first

---

## Reporting Issues

Use the GitHub issue templates:
- **Bug report** — something meshaudit does incorrectly or unexpectedly
- **Feature request** — a new check, flag, or output format

Before opening an issue, check the [Limitations section in README.md](README.md#limitations-v10) to confirm it is in scope.
