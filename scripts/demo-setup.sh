#!/usr/bin/env bash
# demo-setup.sh — Spin up a local minikube + Istio cluster with meshaudit test fixtures.
# Run this once before demoing meshaudit scan.
#
# Prerequisites (install via Homebrew if missing):
#   brew install minikube istioctl
#   brew install --cask docker   # then open Docker Desktop and wait for it to start
#
# Usage:
#   chmod +x scripts/demo-setup.sh
#   ./scripts/demo-setup.sh

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()    { echo -e "${GREEN}[demo-setup]${NC} $*"; }
warning() { echo -e "${YELLOW}[demo-setup]${NC} $*"; }

# ── 1. Start minikube ─────────────────────────────────────────────────────────
if minikube status --format='{{.Host}}' 2>/dev/null | grep -q "Running"; then
  warning "minikube already running — skipping start"
else
  info "Starting minikube (2 CPUs, 4 GB RAM)..."
  minikube start --cpus=2 --memory=4096
fi

# ── 2. Install Istio (minimal profile — control plane only) ───────────────────
if kubectl get namespace istio-system &>/dev/null; then
  warning "istio-system namespace already exists — skipping Istio install"
else
  info "Installing Istio (minimal profile)..."
  istioctl install --set profile=minimal -y
fi

info "Waiting for istiod to be ready..."
kubectl rollout status deployment/istiod -n istio-system --timeout=120s

# ── 3. Create test namespace ──────────────────────────────────────────────────
if kubectl get namespace production &>/dev/null; then
  warning "namespace 'production' already exists — skipping"
else
  info "Creating namespace 'production' with Istio sidecar injection..."
  kubectl create namespace production
  kubectl label namespace production istio-injection=enabled
fi

# ── 4. Deploy test services ───────────────────────────────────────────────────
info "Deploying test services..."

deploy_service() {
  local name=$1
  if kubectl get deployment "$name" -n production &>/dev/null; then
    warning "deployment '$name' already exists — skipping"
  else
    kubectl -n production create deployment "$name" --image=nginx
    kubectl -n production expose deployment "$name" --port=80
  fi
}

deploy_service payments-svc
deploy_service inventory-svc
deploy_service legacy-api

# ── 5. Apply PeerAuthentication fixtures ──────────────────────────────────────
info "Applying PeerAuthentication fixtures..."

kubectl apply -f - <<'EOF'
# Namespace-scoped STRICT — applies to payments-svc and inventory-svc
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: production-strict
  namespace: production
spec:
  mtls:
    mode: STRICT
---
# Workload-scoped DISABLE — overrides namespace policy for legacy-api only
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: legacy-api-disabled
  namespace: production
spec:
  selector:
    matchLabels:
      app: legacy-api
  mtls:
    mode: DISABLE
EOF

# ── 6. Verify ─────────────────────────────────────────────────────────────────
info "Cluster state:"
echo ""
kubectl get peerauthentication -n production
echo ""
kubectl get services -n production
echo ""
info "Setup complete. Run the scan:"
echo ""
echo "  go run . scan --namespace production"
echo "  go run . scan --namespace production --output json"
echo ""
