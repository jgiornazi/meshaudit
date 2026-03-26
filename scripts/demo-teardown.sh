#!/usr/bin/env bash
# demo-teardown.sh — Remove all meshaudit demo fixtures and optionally stop minikube.
#
# Usage:
#   chmod +x scripts/demo-teardown.sh
#   ./scripts/demo-teardown.sh           # removes fixtures, leaves minikube running
#   ./scripts/demo-teardown.sh --stop    # also stops minikube
#   ./scripts/demo-teardown.sh --delete  # also deletes the minikube cluster entirely

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()    { echo -e "${GREEN}[demo-teardown]${NC} $*"; }
warning() { echo -e "${YELLOW}[demo-teardown]${NC} $*"; }

STOP_MINIKUBE=false
DELETE_MINIKUBE=false

for arg in "$@"; do
  case $arg in
    --stop)   STOP_MINIKUBE=true ;;
    --delete) DELETE_MINIKUBE=true ;;
  esac
done

# ── 1. Remove test namespace (deletes services + PeerAuthentications inside) ──
if kubectl get namespace production &>/dev/null; then
  info "Deleting namespace 'production' and all resources inside..."
  kubectl delete namespace production
else
  warning "namespace 'production' not found — nothing to remove"
fi

# ── 2. Optionally stop or delete minikube ─────────────────────────────────────
if $DELETE_MINIKUBE; then
  info "Deleting minikube cluster..."
  minikube delete
elif $STOP_MINIKUBE; then
  info "Stopping minikube..."
  minikube stop
else
  info "minikube left running. Use --stop or --delete to shut it down."
fi

info "Teardown complete."
