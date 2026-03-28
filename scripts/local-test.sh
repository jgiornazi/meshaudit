#!/usr/bin/env bash
# local-test.sh — Functional correctness tests for meshaudit against a local minikube cluster.
#
# Verifies actual audit logic against known fixture state, not just that commands run.
#
# Prerequisites:
#   ./scripts/demo-setup.sh   (provisions minikube + Istio + test fixtures)
#
# Usage:
#   chmod +x scripts/local-test.sh
#   ./scripts/local-test.sh

set -uo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

PASS=0
FAIL=0
BINARY="./meshaudit"
MANIFEST_DIR="$(mktemp -d)"
TEST_VS_NAME="meshaudit-test-vs"

pass() { echo -e "  ${GREEN}PASS${NC}  $*"; ((PASS++)); }
fail() { echo -e "  ${RED}FAIL${NC}  $*"; ((FAIL++)); }
header() { echo -e "\n${BOLD}── $* ${NC}${DIM}──────────────────────────────────────────────────────────${NC}"; }

# Extract a value from JSON using python3
jq_val() {
  python3 -c "import sys,json; d=json.load(sys.stdin); print($1)" 2>/dev/null
}

# Find a finding in the JSON findings array matching service + type, return its severity
finding_severity() {
  local json="$1" service="$2" ftype="$3"
  echo "$json" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for f in data.get('findings', []):
    if f.get('service') == '$service' and f.get('type') == '$ftype':
        print(f.get('severity', ''))
        sys.exit(0)
print('')
" 2>/dev/null
}

# Count findings matching a type+severity
count_findings() {
  local json="$1" ftype="$2" severity="$3"
  echo "$json" | python3 -c "
import sys, json
data = json.load(sys.stdin)
count = sum(1 for f in data.get('findings', [])
            if f.get('type') == '$ftype' and f.get('severity') == '$severity')
print(count)
" 2>/dev/null
}

# Count drift results by status
count_drift() {
  local json="$1" status="$2"
  echo "$json" | python3 -c "
import sys, json
data = json.load(sys.stdin)
count = sum(1 for r in data.get('drift_results', [])
            if r.get('status') == '$status')
print(count)
" 2>/dev/null
}

cleanup() {
  rm -rf "$MANIFEST_DIR"
  kubectl delete virtualservice "$TEST_VS_NAME" -n production --ignore-not-found &>/dev/null || true
}
trap cleanup EXIT

# ── Preflight ─────────────────────────────────────────────────────────────────
header "Preflight"

if ! minikube status --format='{{.Host}}' 2>/dev/null | grep -q "Running"; then
  echo "  minikube is not running. Start it first: ./scripts/demo-setup.sh"
  exit 2
fi

for ns_resource in "namespace/production" "peerauthentication/production-strict" "peerauthentication/legacy-api-disabled"; do
  if ! kubectl get "$ns_resource" -n production &>/dev/null 2>&1; then
    # namespaces aren't namespaced resources
    if ! kubectl get "$ns_resource" &>/dev/null 2>&1; then
      echo "  fixture $ns_resource not found. Run: ./scripts/demo-setup.sh"
      exit 2
    fi
  fi
done

pass "minikube running and fixtures in place"

# ── Build ─────────────────────────────────────────────────────────────────────
header "Build"

if make build 2>/dev/null; then
  pass "make build succeeds"
else
  fail "make build failed — cannot continue"
  exit 2
fi

# ── Capture scan JSON once (reused across all scan tests) ─────────────────────
SCAN_JSON=$("$BINARY" scan --namespace production --output json 2>&1)

if ! echo "$SCAN_JSON" | python3 -m json.tool &>/dev/null; then
  fail "scan --output json is not valid JSON — cannot run functional tests"
  echo "$SCAN_JSON"
  exit 2
fi

# ── mTLS posture correctness ───────────────────────────────────────────────────
header "mTLS posture — per-service severity"

# Known fixture: namespace-scoped STRICT PA covers payments-svc and inventory-svc.
# Workload-scoped DISABLE PA overrides legacy-api.
for svc in payments-svc inventory-svc; do
  sev=$(finding_severity "$SCAN_JSON" "$svc" "mtls")
  if [[ "$sev" == "PASS" ]]; then
    pass "$svc reported as PASS (STRICT mTLS)"
  else
    fail "$svc expected PASS, got '$sev'"
  fi
done

sev=$(finding_severity "$SCAN_JSON" "legacy-api" "mtls")
if [[ "$sev" == "FAIL" ]]; then
  pass "legacy-api reported as FAIL (mTLS DISABLED)"
else
  fail "legacy-api expected FAIL, got '$sev'"
fi

# ── Authz findings ─────────────────────────────────────────────────────────────
header "AuthorizationPolicy — no policies deployed → zero authz findings"

authz_count=$(echo "$SCAN_JSON" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(sum(1 for f in data.get('findings', []) if f.get('type') == 'authz'))
" 2>/dev/null)

if [[ "$authz_count" -eq 0 ]]; then
  pass "zero authz findings (no AuthorizationPolicies deployed)"
else
  fail "expected 0 authz findings, got $authz_count"
fi

# ── Score and band ─────────────────────────────────────────────────────────────
header "Posture score — formula correctness"

# Expected: 100 - (1 DISABLED × 20) = 80 → FAIR
score=$(echo "$SCAN_JSON" | jq_val "d['score']")
band=$(echo "$SCAN_JSON" | jq_val "d['score_band']")

if [[ "$score" -eq 80 ]]; then
  pass "score is 80 (100 - 1×DISABLED×20)"
else
  fail "expected score 80, got $score"
fi

if [[ "$band" == "FAIR" ]]; then
  pass "score band is FAIR (70–89)"
else
  fail "expected band FAIR, got $band"
fi

# ── Summary counts ─────────────────────────────────────────────────────────────
header "Summary counts"

summary_pass=$(echo "$SCAN_JSON" | jq_val "d['summary']['pass']")
summary_warn=$(echo "$SCAN_JSON" | jq_val "d['summary']['warn']")
summary_fail=$(echo "$SCAN_JSON" | jq_val "d['summary']['fail']")

if [[ "$summary_pass" -eq 2 ]]; then
  pass "summary.pass = 2"
else
  fail "expected summary.pass = 2, got $summary_pass"
fi

if [[ "$summary_warn" -eq 0 ]]; then
  pass "summary.warn = 0"
else
  fail "expected summary.warn = 0, got $summary_warn"
fi

if [[ "$summary_fail" -eq 1 ]]; then
  pass "summary.fail = 1"
else
  fail "expected summary.fail = 1, got $summary_fail"
fi

# ── suggested_fix populated ────────────────────────────────────────────────────
header "suggested_fix populated on FAIL findings"

fix=$(echo "$SCAN_JSON" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for f in data.get('findings', []):
    if f.get('service') == 'legacy-api':
        print(f.get('suggested_fix', ''))
" 2>/dev/null)

if [[ -n "$fix" ]]; then
  pass "legacy-api has suggested_fix: '$fix'"
else
  fail "legacy-api missing suggested_fix"
fi

# ── Exit codes ────────────────────────────────────────────────────────────────
header "Exit codes"

"$BINARY" scan --namespace production &>/dev/null
if [[ $? -eq 0 ]]; then
  pass "scan exits 0 without --fail-on-warn"
else
  fail "scan expected exit 0, got $?"
fi

"$BINARY" scan --namespace production --fail-on-warn &>/dev/null
if [[ $? -eq 1 ]]; then
  pass "--fail-on-warn exits 1 (legacy-api FAIL present)"
else
  fail "--fail-on-warn expected exit 1"
fi

# min-score below actual score → exit 0
"$BINARY" scan --namespace production --min-score 50 &>/dev/null
if [[ $? -eq 0 ]]; then
  pass "--min-score 50 exits 0 (score 80 ≥ 50)"
else
  fail "--min-score 50 expected exit 0"
fi

# min-score above actual score → exit 1
"$BINARY" scan --namespace production --min-score 90 &>/dev/null
if [[ $? -eq 1 ]]; then
  pass "--min-score 90 exits 1 (score 80 < 90)"
else
  fail "--min-score 90 expected exit 1"
fi

# bad output format → exit 2
"$BINARY" scan --namespace production --output badformat &>/dev/null
if [[ $? -eq 2 ]]; then
  pass "unknown --output format exits 2"
else
  fail "unknown --output format expected exit 2"
fi

# ── Drift: MANIFEST_ONLY ───────────────────────────────────────────────────────
header "Drift — MANIFEST_ONLY (VS in git, not in cluster)"

cat > "$MANIFEST_DIR/manifest-only.yaml" <<EOF
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: payments-vs
  namespace: production
spec:
  hosts: [payments-svc]
  http:
    - route:
        - destination:
            host: payments-svc
EOF

drift_json=$("$BINARY" drift --git-path "$MANIFEST_DIR" --namespace production --output json 2>&1)

manifest_only=$(count_drift "$drift_json" "MANIFEST_ONLY")
if [[ "$manifest_only" -eq 1 ]]; then
  pass "payments-vs reported as MANIFEST_ONLY"
else
  fail "expected 1 MANIFEST_ONLY result, got $manifest_only"
fi

# ── Drift: LIVE_ONLY and IN_SYNC ───────────────────────────────────────────────
header "Drift — LIVE_ONLY and IN_SYNC (VS applied to cluster)"

# Apply a VS to the cluster.
kubectl apply -f - &>/dev/null <<EOF
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: $TEST_VS_NAME
  namespace: production
spec:
  hosts: [payments-svc]
  http:
    - timeout: 10s
      route:
        - destination:
            host: payments-svc
EOF

sleep 2  # allow API server to settle

# Empty manifest dir → the live VS has no desired counterpart → LIVE_ONLY
EMPTY_DIR="$(mktemp -d)"
drift_json=$("$BINARY" drift --git-path "$EMPTY_DIR" --namespace production --output json 2>&1)
rm -rf "$EMPTY_DIR"

live_only=$(count_drift "$drift_json" "LIVE_ONLY")
if [[ "$live_only" -ge 1 ]]; then
  pass "$TEST_VS_NAME reported as LIVE_ONLY (not in manifests)"
else
  fail "expected at least 1 LIVE_ONLY result, got $live_only"
fi

# Manifest dir with identical VS → IN_SYNC
IN_SYNC_DIR="$(mktemp -d)"
cat > "$IN_SYNC_DIR/test-vs.yaml" <<EOF
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: $TEST_VS_NAME
  namespace: production
spec:
  hosts: [payments-svc]
  http:
    - timeout: 10s
      route:
        - destination:
            host: payments-svc
EOF

drift_json=$("$BINARY" drift --git-path "$IN_SYNC_DIR" --namespace production --output json 2>&1)
rm -rf "$IN_SYNC_DIR"

in_sync=$(count_drift "$drift_json" "IN_SYNC")
if [[ "$in_sync" -ge 1 ]]; then
  pass "$TEST_VS_NAME reported as IN_SYNC (live matches manifest)"
else
  fail "expected at least 1 IN_SYNC result, got $in_sync"
fi

# ── Drift: DRIFT_DETECTED ──────────────────────────────────────────────────────
header "Drift — DRIFT_DETECTED (spec changed in manifests)"

DRIFT_DIR="$(mktemp -d)"
cat > "$DRIFT_DIR/test-vs.yaml" <<EOF
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: $TEST_VS_NAME
  namespace: production
spec:
  hosts: [payments-svc]
  http:
    - timeout: 5s
      route:
        - destination:
            host: payments-svc
EOF

drift_json=$("$BINARY" drift --git-path "$DRIFT_DIR" --namespace production --output json 2>&1)
rm -rf "$DRIFT_DIR"

drifted=$(count_drift "$drift_json" "DRIFT_DETECTED")
if [[ "$drifted" -ge 1 ]]; then
  pass "$TEST_VS_NAME reported as DRIFT_DETECTED (timeout 10s → 5s)"
else
  fail "expected at least 1 DRIFT_DETECTED result, got $drifted"
fi

# Verify diffs are populated
has_diffs=$(echo "$drift_json" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data.get('drift_results', []):
    if r.get('status') == 'DRIFT_DETECTED' and r.get('diffs'):
        print('yes')
        sys.exit(0)
print('no')
" 2>/dev/null)

if [[ "$has_diffs" == "yes" ]]; then
  pass "DRIFT_DETECTED result includes field-level diffs"
else
  fail "DRIFT_DETECTED result missing diffs"
fi

# ── Drift: --fail-on-warn ──────────────────────────────────────────────────────
header "Drift — exit codes"

# Manifest with a VS not in cluster → MANIFEST_ONLY → should exit 1 with --fail-on-warn
FAILTEST_DIR="$(mktemp -d)"
cat > "$FAILTEST_DIR/missing.yaml" <<EOF
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: does-not-exist
  namespace: production
spec:
  hosts: [missing-svc]
EOF

"$BINARY" drift --git-path "$FAILTEST_DIR" --namespace production --fail-on-warn &>/dev/null
if [[ $? -eq 1 ]]; then
  pass "drift --fail-on-warn exits 1 when drift present"
else
  fail "drift --fail-on-warn expected exit 1"
fi
rm -rf "$FAILTEST_DIR"

# Missing --git-path → exit 2
"$BINARY" drift &>/dev/null
if [[ $? -eq 2 ]]; then
  pass "drift without --git-path exits 2"
else
  fail "drift without --git-path expected exit 2"
fi

# Nonexistent path → exit 2
"$BINARY" drift --git-path /nonexistent/path &>/dev/null
if [[ $? -eq 2 ]]; then
  pass "drift with nonexistent --git-path exits 2"
else
  fail "drift with nonexistent --git-path expected exit 2"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}Results: ${GREEN}${PASS} passed${NC}  ${RED}${FAIL} failed${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

if [[ $FAIL -gt 0 ]]; then
  exit 1
fi
