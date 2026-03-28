# meshaudit — Pre-Release Task List

**Goal:** Get meshaudit to a state where it builds, all CI passes, and can be run against a local minikube cluster. Homebrew distribution is out of scope for now.

---

## Task 1 — Add `LICENSE` file (MIT)
**Blocker for:** GoReleaser archive step
**Status:** ✅

Create `LICENSE` at the repo root with standard MIT license text.

---

## Task 2 — Fix coverage gate (reach ≥ 75%)
**Blocker for:** CI green on `main`
**Status:** ✅ — 75.4% total (`internal/k8s` raised from 60.9% → 67.4% via injectable `exitFn` + forbidden-branch tests)

---

## Task 3 — Tag v1.0.0
**Status:** ⬜
**Depends on:** Tasks 1, 2

```bash
# Pre-tag checks
go test -race ./...
golangci-lint run ./...
goreleaser check

# Tag
git tag v1.0.0
git push origin v1.0.0
```

For local minikube testing without a release:
```bash
make build VERSION=v1.0.0
./meshaudit scan --namespace production
```

---

## Dependency Graph

```
Task 1 (LICENSE)      — no deps  ← do now
Task 2 (coverage)     — no deps  ← do now
Task 3 (v1.0.0 tag)  — depends on 1, 2
```
