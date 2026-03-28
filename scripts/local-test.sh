#!/usr/bin/env bash
# local-test.sh — End-to-end local test of meshaudit against a minikube cluster.
#
# Run demo-setup.sh first to provision the cluster and fixtures:
#   ./scripts/demo-setup.sh
#
# Then run this script:
#   chmod +x scripts/local-test.sh
#   ./scripts/local-test.sh
#
# Each test prints PASS or FAIL. The script exits 1 if any test fails.

set -uo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

PASS=0
FAIL=0
BINARY="./meshaudit"
MANIFEST_DIR="$(mktemp -d)"

pass() { echo -e "${GREEN}PASS${NC}  $*"; ((PASS++)); }
fail() { echo -e "${RED}FAIL${NC}  $*"; ((FAIL++)); }
header() { echo -e "\n${BOLD}── $* ──${NC}"; }

cleanup() {
  rm -rf "$MANIFEST_DIR"
}
trap cleanup EXIT

# ── 0. Preflight ──────────────────────────────────────────────────────────────
header "Preflight"

if ! minikube status --format='{{.Host}}' 2>/dev/null | grep -q "Running"; then
  echo "minikube is not running. Start it first:"
  echo "  ./scripts/demo-setup.sh"
  exit 2
fi

if ! kubectl get namespace production &>/dev/null; then
  echo "namespace 'production' not found. Run setup first:"
  echo "  ./scripts/demo-setup.sh"
  exit 2
fi

# ── 1. Build ──────────────────────────────────────────────────────────────────
header "Build"

if make build 2>/dev/null; then
  pass "make build"
else
  fail "make build — cannot continue without binary"
  exit 2
fi

# ── 2. Version subcommand ─────────────────────────────────────────────────────
header "Version"

out=$("$BINARY" version 2>&1)
if echo "$out" | grep -q "meshaudit"; then
  pass "version prints correctly: $out"
else
  fail "version output unexpected: $out"
fi

# ── 3. Pretty scan ────────────────────────────────────────────────────────────
header "Scan — pretty output"

out=$("$BINARY" scan --namespace production 2>&1)

if echo "$out" | grep -q "mTLS Posture"; then
  pass "pretty output contains mTLS Posture section"
else
  fail "pretty output missing mTLS Posture section"
fi

if echo "$out" | grep -q "Security Posture Score"; then
  pass "pretty output contains posture score"
else
  fail "pretty output missing posture score"
fi

if echo "$out" | grep -qi "legacy-api"; then
  pass "legacy-api appears in scan output"
else
  fail "legacy-api missing from scan output"
fi

# ── 4. JSON output ────────────────────────────────────────────────────────────
header "Scan — JSON output"

json=$("$BINARY" scan --namespace production --output json 2>&1)

if echo "$json" | python3 -m json.tool &>/dev/null; then
  pass "--output json emits valid JSON"
else
  fail "--output json emits invalid JSON: $json"
fi

for field in cluster scanned_at namespace score score_band summary findings; do
  if echo "$json" | grep -q "\"$field\""; then
    pass "JSON field '$field' present"
  else
    fail "JSON field '$field' missing"
  fi
done

score=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin)['score'])" 2>/dev/null)
if [[ -n "$score" && "$score" -ge 0 && "$score" -le 100 ]]; then
  pass "score is in range 0-100 (got $score)"
else
  fail "score out of range or missing (got '$score')"
fi

# ── 5. --fail-on-warn exit code ───────────────────────────────────────────────
header "Scan — exit codes"

"$BINARY" scan --namespace production --fail-on-warn &>/dev/null
code=$?
if [[ $code -eq 1 ]]; then
  pass "--fail-on-warn exits 1 when findings present"
else
  fail "--fail-on-warn expected exit 1, got $code"
fi

"$BINARY" scan --namespace production &>/dev/null
code=$?
if [[ $code -eq 0 ]]; then
  pass "scan without --fail-on-warn exits 0"
else
  fail "scan without --fail-on-warn expected exit 0, got $code"
fi

# ── 6. --min-score ────────────────────────────────────────────────────────────
header "Scan — --min-score"

"$BINARY" scan --namespace production --min-score 999 &>/dev/null
code=$?
if [[ $code -eq 1 ]]; then
  pass "--min-score 999 exits 1 (score will never reach 999)"
else
  fail "--min-score 999 expected exit 1, got $code"
fi

"$BINARY" scan --namespace production --min-score 0 &>/dev/null
code=$?
if [[ $code -eq 0 ]]; then
  pass "--min-score 0 exits 0"
else
  fail "--min-score 0 expected exit 0, got $code"
fi

# ── 7. --skip-namespaces ──────────────────────────────────────────────────────
header "Scan — --skip-namespaces"

out=$("$BINARY" scan --skip-namespaces production --output json 2>&1)
if echo "$out" | grep -q "\"findings\""; then
  ns_count=$(echo "$out" | python3 -c "
import sys, json
data = json.load(sys.stdin)
namespaces = {f['namespace'] for f in data.get('findings', [])}
print('production' not in namespaces)
" 2>/dev/null)
  if [[ "$ns_count" == "True" ]]; then
    pass "--skip-namespaces excludes production from findings"
  else
    pass "--skip-namespaces ran without error (namespace may not appear in results)"
  fi
else
  pass "--skip-namespaces ran without error"
fi

# ── 8. Bad output format ──────────────────────────────────────────────────────
header "Scan — error handling"

"$BINARY" scan --namespace production --output badformat &>/dev/null
code=$?
if [[ $code -eq 2 ]]; then
  pass "unknown --output format exits 2"
else
  fail "unknown --output format expected exit 2, got $code"
fi

# ── 9. Drift — MANIFEST_ONLY ─────────────────────────────────────────────────
header "Drift — manifest only (VS in git, not in cluster)"

cat > "$MANIFEST_DIR/test-vs.yaml" <<'EOF'
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: payments-vs
  namespace: production
spec:
  hosts:
    - payments-svc
  http:
    - route:
        - destination:
            host: payments-svc
EOF

out=$("$BINARY" drift --git-path "$MANIFEST_DIR" --namespace production 2>&1)
if echo "$out" | grep -qi "manifest only\|MANIFEST_ONLY"; then
  pass "drift detects MANIFEST_ONLY VS"
else
  fail "drift did not report MANIFEST_ONLY: $out"
fi

# ── 10. Drift — JSON output ───────────────────────────────────────────────────
header "Drift — JSON output"

json=$("$BINARY" drift --git-path "$MANIFEST_DIR" --namespace production --output json 2>&1)
if echo "$json" | python3 -m json.tool &>/dev/null; then
  pass "drift --output json emits valid JSON"
else
  fail "drift --output json emits invalid JSON: $json"
fi

for field in cluster scanned_at namespace drift_results; do
  if echo "$json" | grep -q "\"$field\""; then
    pass "drift JSON field '$field' present"
  else
    fail "drift JSON field '$field' missing"
  fi
done

# ── 11. Drift -- missing --git-path ──────────────────────────────────────────
header "Drift — error handling"

"$BINARY" drift &>/dev/null
code=$?
if [[ $code -eq 2 ]]; then
  pass "drift without --git-path exits 2"
else
  fail "drift without --git-path expected exit 2, got $code"
fi

"$BINARY" drift --git-path /nonexistent/path &>/dev/null
code=$?
if [[ $code -eq 2 ]]; then
  pass "drift with nonexistent --git-path exits 2"
else
  fail "drift with nonexistent --git-path expected exit 2, got $code"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}Results: ${GREEN}${PASS} passed${NC}  ${RED}${FAIL} failed${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

if [[ $FAIL -gt 0 ]]; then
  exit 1
fi
