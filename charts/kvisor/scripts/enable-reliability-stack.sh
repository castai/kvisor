#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# enable-reliability-stack.sh
#
# Idempotent script to install or upgrade the kvisor reliability metrics stack.
# Handles the ClickHouse Operator CRD chicken-and-egg problem:
#
#   1. If the ClickHouseInstallation CRD already exists → skip operator install
#   2. If not → install just the operator (Phase 1), wait for CRDs, then proceed
#   3. Install or upgrade the full reliability stack (Phase 2)
#
# Supports both fresh installs (with --api-key and --cluster-id) and upgrades
# of existing kvisor releases.
#
# Usage:
#   ./enable-reliability-stack.sh [options]
#
# Options:
#   -n, --namespace         Kubernetes namespace (default: castai-agent)
#   -r, --release           Helm release name (default: castai-kvisor)
#   -c, --chart             Helm chart reference (default: castai-helm/castai-kvisor)
#       --context           kubectl/helm context (optional)
#   -f, --values-file       Helm values file (for fresh install or overrides)
#       --api-key           CAST AI API key (inline, for fresh install)
#       --api-key-secret    Pre-existing Secret name containing API_KEY (for fresh install)
#       --cluster-id        CAST AI cluster ID (inline, for fresh install)
#       --cluster-id-secret Pre-existing Secret name containing CLUSTER_ID (for fresh install)
#       --grpc-addr         CAST AI gRPC address (optional, for fresh install)
#       --obi-profile       OBI sizing profile: auto, small, medium, large, xlarge (default: auto)
#                           'auto' runs obi-sizing-report.sh to detect the best profile
#       --dynamic-sizing    Enable OBI dynamic sizing (default: false)
#       --dry-run           Print commands without executing
#       --skip-repo         Skip helm repo add/update
#   -h, --help              Show this help
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Defaults ─────────────────────────────────────────────────────────────────
NAMESPACE="castai-agent"
RELEASE="castai-kvisor"
CHART="castai-helm/castai-kvisor"
CONTEXT=""
VALUES_FILE=""
API_KEY=""
API_KEY_SECRET=""
CLUSTER_ID=""
CLUSTER_ID_SECRET=""
GRPC_ADDR=""
OBI_PROFILE="auto"
DYNAMIC_SIZING="false"
DRY_RUN=""
SKIP_REPO=""
INSTALL_MODE=""

# ── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# ── Helpers ──────────────────────────────────────────────────────────────────
info()  { printf "${BLUE}ℹ${NC}  %s\n" "$*"; }
ok()    { printf "${GREEN}✓${NC}  %s\n" "$*"; }
warn()  { printf "${YELLOW}⚠${NC}  %s\n" "$*"; }
err()   { printf "${RED}✗${NC}  %s\n" "$*" >&2; }
step()  { printf "\n${BOLD}${CYAN}━━━ %s${NC}\n" "$*"; }

usage() {
  sed -n '/^# Usage:/,/^# ─/p' "$0" | sed '$ d' | sed 's/^# //' | sed 's/^#//'
  exit 0
}

# ── Parse Args ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--namespace)       NAMESPACE="$2"; shift 2 ;;
    -r|--release)         RELEASE="$2"; shift 2 ;;
    -c|--chart)           CHART="$2"; shift 2 ;;
    --context)            CONTEXT="$2"; shift 2 ;;
    -f|--values-file)     VALUES_FILE="$2"; shift 2 ;;
    --api-key)            API_KEY="$2"; shift 2 ;;
    --api-key-secret)     API_KEY_SECRET="$2"; shift 2 ;;
    --cluster-id)         CLUSTER_ID="$2"; shift 2 ;;
    --cluster-id-secret)  CLUSTER_ID_SECRET="$2"; shift 2 ;;
    --grpc-addr)          GRPC_ADDR="$2"; shift 2 ;;
    --obi-profile)        OBI_PROFILE="$2"; shift 2 ;;
    --dynamic-sizing)     DYNAMIC_SIZING="true"; shift ;;
    --dry-run)            DRY_RUN="true"; shift ;;
    --skip-repo)          SKIP_REPO="true"; shift ;;
    -h|--help)            usage ;;
    *)                    err "Unknown option: $1"; usage ;;
  esac
done

# ── Build kubectl/helm context flags ─────────────────────────────────────────
# Intentionally unquoted in usage — empty string collapses to no argument
KUBECTL_CTX=""
HELM_CTX=""
if [[ -n "$CONTEXT" ]]; then
  KUBECTL_CTX="--context $CONTEXT"
  HELM_CTX="--kube-context $CONTEXT"
fi

run_cmd() {
  if [[ -n "$DRY_RUN" ]]; then
    printf "${YELLOW}[dry-run]${NC} %s\n" "$*"
  else
    eval "$@"
  fi
}

# Build helm flags for CAST AI credentials (fresh install only)
# Outputs flags to stdout — caller captures via $()
build_creds_flags() {
  if [[ -n "$VALUES_FILE" ]]; then
    echo "-f $VALUES_FILE"
  fi

  # API key: inline value or pre-existing Secret ref
  if [[ -n "$API_KEY" ]]; then
    echo "--set castai.apiKey=$API_KEY"
  elif [[ -n "$API_KEY_SECRET" ]]; then
    echo "--set castai.apiKeySecretRef=$API_KEY_SECRET"
  fi

  # Cluster ID: inline value or pre-existing Secret ref
  if [[ -n "$CLUSTER_ID" ]]; then
    echo "--set castai.clusterID=$CLUSTER_ID"
  elif [[ -n "$CLUSTER_ID_SECRET" ]]; then
    echo "--set castai.clusterIdSecretKeyRef.name=$CLUSTER_ID_SECRET"
  fi

  # Optional gRPC address
  if [[ -n "$GRPC_ADDR" ]]; then
    echo "--set castai.grpcAddr=$GRPC_ADDR"
  fi
}

# ── Preflight checks ────────────────────────────────────────────────────────
step "Preflight Checks"

command -v kubectl >/dev/null 2>&1 || { err "kubectl not found"; exit 1; }
command -v helm >/dev/null 2>&1    || { err "helm not found"; exit 1; }
ok "kubectl and helm found"

# Verify cluster connectivity
if ! kubectl $KUBECTL_CTX cluster-info >/dev/null 2>&1; then
  err "Cannot connect to cluster${CONTEXT:+ (context: $CONTEXT)}"
  exit 1
fi
CLUSTER_NAME=$(kubectl $KUBECTL_CTX config current-context 2>/dev/null || echo "unknown")
ok "Connected to cluster: $CLUSTER_NAME"

# ── Helm repo ───────────────────────────────────────────────────────────────
if [[ -z "$SKIP_REPO" ]]; then
  step "Helm Repository"
  run_cmd "helm repo add castai-helm https://castai.github.io/helm-charts 2>/dev/null || true"
  run_cmd "helm repo update castai-helm"
  ok "Helm repo up to date"
fi

# ── Check existing release ──────────────────────────────────────────────────
step "Checking Existing Release"

if helm $HELM_CTX status "$RELEASE" -n "$NAMESPACE" >/dev/null 2>&1; then
  CURRENT_REVISION=$(helm $HELM_CTX history "$RELEASE" -n "$NAMESPACE" --max 1 -o json 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['revision'])" 2>/dev/null || echo "?")
  ok "Release '$RELEASE' found (revision $CURRENT_REVISION) — upgrade mode"
else
  warn "Release '$RELEASE' not found in namespace '$NAMESPACE'"
  # For fresh install, we need credentials from one of:
  #   1. --values-file (contains castai.apiKey/apiKeySecretRef + clusterID)
  #   2. --api-key + --cluster-id (inline)
  #   3. --api-key-secret + --cluster-id-secret (pre-existing Secrets)
  HAS_CREDS=""
  [[ -n "$VALUES_FILE" ]] && HAS_CREDS="true"
  [[ -n "$API_KEY" || -n "$API_KEY_SECRET" ]] && [[ -n "$CLUSTER_ID" || -n "$CLUSTER_ID_SECRET" ]] && HAS_CREDS="true"
  if [[ -z "$HAS_CREDS" ]]; then
    err "Fresh install requires credentials. Provide one of:"
    err "  --values-file <file>                     (values file with castai.* config)"
    err "  --api-key <key> --cluster-id <id>         (inline credentials)"
    err "  --api-key-secret <name> --cluster-id-secret <name>  (pre-existing Secrets)"
    exit 1
  fi
  INSTALL_MODE="true"
  ok "Fresh install mode — will create release '$RELEASE'"
fi

# ── Phase 1: CRD Detection & Operator Bootstrap ─────────────────────────────
step "Phase 1: ClickHouse Operator CRD Check"

CRD_EXISTS=""
if kubectl $KUBECTL_CTX get crd clickhouseinstallations.clickhouse.altinity.com >/dev/null 2>&1; then
  CRD_EXISTS="true"
  ok "ClickHouseInstallation CRD already exists — skipping operator install"
else
  warn "ClickHouseInstallation CRD not found"
  info "Installing ClickHouse operator first (Phase 1)..."
  info "This deploys ONLY the operator + CRD, without enabling the full stack."

  # Phase 1: Install just the operator to register the CRD.
  # We explicitly disable install.enabled so the ClickHouseInstallation CR isn't created yet.
  PHASE1_CMD="helm upgrade --install $RELEASE $CHART \\
    -n $NAMESPACE --create-namespace \\
    $HELM_CTX"

  # Fresh installs need credentials; upgrades reuse existing values
  if [[ -n "$INSTALL_MODE" ]]; then
    PHASE1_CMD="$PHASE1_CMD $(build_creds_flags)"
  else
    PHASE1_CMD="$PHASE1_CMD \\
    --reset-then-reuse-values"
  fi

  PHASE1_CMD="$PHASE1_CMD \\
    --set reliabilityMetrics.enabled=true \\
    --set reliabilityMetrics.operator.enabled=true \\
    --set reliabilityMetrics.install.enabled=false \\
    --set reliabilityMetrics.exporter.enabled=false"

  run_cmd "$PHASE1_CMD"

  if [[ -z "$DRY_RUN" ]]; then
    info "Waiting for CRD to be registered..."
    TRIES=0
    MAX_TRIES=30
    while ! kubectl $KUBECTL_CTX get crd clickhouseinstallations.clickhouse.altinity.com >/dev/null 2>&1; do
      TRIES=$((TRIES + 1))
      if [[ $TRIES -ge $MAX_TRIES ]]; then
        err "Timed out waiting for ClickHouseInstallation CRD (${MAX_TRIES}s)"
        err "Check operator logs: kubectl logs -n $NAMESPACE -l app=clickhouse-operator"
        exit 1
      fi
      printf "."
      sleep 1
    done
    echo ""
    ok "ClickHouseInstallation CRD is now available"
  fi
fi

# ── Auto-detect OBI profile ──────────────────────────────────────────────────
if [[ "$OBI_PROFILE" == "auto" ]]; then
  step "Auto-detecting OBI Profile"
  SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
  SIZING_SCRIPT="$SCRIPT_DIR/obi-sizing-report.sh"

  if [[ ! -x "$SIZING_SCRIPT" ]]; then
    warn "obi-sizing-report.sh not found at $SIZING_SCRIPT"
    warn "Falling back to profile 'medium'"
    OBI_PROFILE="medium"
  else
    SIZING_ARGS="--machine"
    [[ -n "$CONTEXT" ]] && SIZING_ARGS="$SIZING_ARGS --context $CONTEXT"

    info "Running: obi-sizing-report.sh $SIZING_ARGS"
    SIZING_OUTPUT=$("$SIZING_SCRIPT" $SIZING_ARGS 2>/dev/null) || {
      warn "obi-sizing-report.sh failed; falling back to profile 'medium'"
      OBI_PROFILE="medium"
      SIZING_OUTPUT=""
    }

    if [[ -n "$SIZING_OUTPUT" ]]; then
      # Parse: PROFILE=small DYNAMIC=false MAX_PROCS=2 MIN_PROCS=0 NODES=9
      SIZING_PROFILE="" SIZING_DYNAMIC="" SIZING_MAX_PROCS="" SIZING_MIN_PROCS="" SIZING_NODES=""
      while IFS='=' read -r key val; do
        case "$key" in
          PROFILE)   SIZING_PROFILE="$val" ;;
          DYNAMIC)   SIZING_DYNAMIC="$val" ;;
          MAX_PROCS) SIZING_MAX_PROCS="$val" ;;
          MIN_PROCS) SIZING_MIN_PROCS="$val" ;;
          NODES)     SIZING_NODES="$val" ;;
        esac
      done < <(echo "$SIZING_OUTPUT" | tr ' ' '\n')
      OBI_PROFILE="${SIZING_PROFILE:-medium}"

      # Use dynamic sizing recommendation unless user explicitly set --dynamic-sizing
      if [[ "$DYNAMIC_SIZING" == "false" && "${SIZING_DYNAMIC:-false}" == "true" ]]; then
        DYNAMIC_SIZING="true"
        info "High variance detected — enabling dynamic sizing (recommended)"
      fi

      ok "Auto-detected profile: $OBI_PROFILE (max ${SIZING_MAX_PROCS:-?} procs across ${SIZING_NODES:-?} nodes)"
    fi
  fi
fi

# ── Phase 2: Enable Full Reliability Stack ───────────────────────────────────
step "Phase 2: Enabling Full Reliability Stack"

# Build the helm command with all reliability flags
HELM_CMD="helm upgrade --install $RELEASE $CHART \\
  -n $NAMESPACE --create-namespace \\
  $HELM_CTX"

# Fresh installs need credentials; upgrades reuse existing values
if [[ -n "$INSTALL_MODE" ]]; then
  HELM_CMD="$HELM_CMD $(build_creds_flags)"
else
  HELM_CMD="$HELM_CMD \\
  --reset-then-reuse-values"
fi

HELM_CMD="$HELM_CMD \\
  --set agent.reliabilityMetrics.enabled=true \\
  --set agent.reliabilityMetrics.obi.sizingProfile=$OBI_PROFILE \\
  --set agent.reliabilityMetrics.obi.dynamicSizing=$DYNAMIC_SIZING \\
  --set controller.reliabilityMetrics.enabled=true \\
  --set reliabilityMetrics.enabled=true \\
  --set reliabilityMetrics.install.enabled=true \\
  --set reliabilityMetrics.exporter.enabled=true"

# If operator was already present (external), don't install ours
if [[ -n "$CRD_EXISTS" ]]; then
  HELM_CMD="$HELM_CMD \\
  --set reliabilityMetrics.operator.enabled=false"
  info "Using existing ClickHouse operator (not installing chart's operator)"
else
  HELM_CMD="$HELM_CMD \\
  --set reliabilityMetrics.operator.enabled=true"
  info "ClickHouse operator enabled (installed in Phase 1)"
fi

info "OBI sizing profile: $OBI_PROFILE"
info "Dynamic sizing: $DYNAMIC_SIZING"
echo ""

run_cmd "$HELM_CMD"

# ── Phase 3: Verify Rollout ──────────────────────────────────────────────────
if [[ -z "$DRY_RUN" ]]; then
  step "Phase 3: Verifying Rollout"

  info "Waiting for agent DaemonSet rollout..."
  kubectl $KUBECTL_CTX rollout status daemonset/${RELEASE}-agent -n "$NAMESPACE" --timeout=120s 2>/dev/null || {
    warn "DaemonSet rollout not complete within 120s. Check pods:"
    kubectl $KUBECTL_CTX get pods -n "$NAMESPACE" -l app.kubernetes.io/name=${RELEASE}-agent
  }

  echo ""
  info "Pod status:"
  kubectl $KUBECTL_CTX get pods -n "$NAMESPACE" -l "app.kubernetes.io/instance=${RELEASE##castai-}" 2>/dev/null || \
    kubectl $KUBECTL_CTX get pods -n "$NAMESPACE" 2>/dev/null | grep -E "kvisor|clickhouse"

  echo ""
  AGENT_PODS=$(kubectl $KUBECTL_CTX get pods -n "$NAMESPACE" -l app.kubernetes.io/name=${RELEASE}-agent -o name 2>/dev/null | head -1)
  if [[ -n "$AGENT_PODS" ]]; then
    POD_NAME="${AGENT_PODS##*/}"
    info "Checking OBI container on $POD_NAME..."
    OBI_LOG=$(kubectl $KUBECTL_CTX logs -n "$NAMESPACE" "$POD_NAME" -c obi 2>/dev/null | head -3)
    if [[ -n "$OBI_LOG" ]]; then
      ok "OBI container running"
      echo "$OBI_LOG" | head -2 | sed 's/^/   /'
    else
      warn "OBI container not producing logs yet (may still be starting)"
    fi
  fi
fi

# ── Summary ──────────────────────────────────────────────────────────────────
step "Done"
echo ""
if [[ -n "$INSTALL_MODE" ]]; then
  MODE_LABEL="install"
  printf "${GREEN}${BOLD}Reliability metrics stack installed!${NC}\n"
else
  MODE_LABEL="upgrade"
  printf "${GREEN}${BOLD}Reliability metrics stack upgraded!${NC}\n"
fi
echo ""
echo "  Mode:           $MODE_LABEL"
echo "  Namespace:      $NAMESPACE"
echo "  Release:        $RELEASE"
echo "  OBI profile:    $OBI_PROFILE"
echo "  Dynamic sizing: $DYNAMIC_SIZING"
echo ""
echo "Next steps:"
echo "  • Verify ClickHouse is ready:  kubectl get chi -n $NAMESPACE"
echo "  • Check OBI logs:              kubectl logs -n $NAMESPACE <agent-pod> -c obi"
echo "  • Run OBI sizing report:       ./charts/kvisor/scripts/obi-sizing-report.sh"
echo "  • View sizing guide:           docs/obi-sizing.md"
echo ""
