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
# of existing kvisor releases. Auto-detects whether kvisor is installed
# standalone or via the CAST AI umbrella chart and adjusts accordingly.
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
#       --values-prefix     Prefix for all --set keys (for umbrella charts).
#                           e.g. --values-prefix autoscaler.castai-kvisor
#                           When set, keys like agent.reliabilityMetrics.enabled become
#                           autoscaler.castai-kvisor.agent.reliabilityMetrics.enabled
#       --chart-version     Pin chart version (e.g. 0.33.21). Default: auto-detected
#                           from the currently deployed release to avoid upgrading
#                           unrelated components.
#       --upgrade-chart     Upgrade to the latest chart version instead of pinning to
#                           the currently deployed version.
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
VALUES_PREFIX=""
CHART_VERSION=""
UPGRADE_CHART=""
DRY_RUN=""
SKIP_REPO=""
INSTALL_MODE=""
USER_SET_RELEASE=""
USER_SET_CHART=""

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
    -r|--release)         RELEASE="$2"; USER_SET_RELEASE="true"; shift 2 ;;
    -c|--chart)           CHART="$2"; USER_SET_CHART="true"; shift 2 ;;
    --context)            CONTEXT="$2"; shift 2 ;;
    -f|--values-file)     VALUES_FILE="$2"; shift 2 ;;
    --api-key)            API_KEY="$2"; shift 2 ;;
    --api-key-secret)     API_KEY_SECRET="$2"; shift 2 ;;
    --cluster-id)         CLUSTER_ID="$2"; shift 2 ;;
    --cluster-id-secret)  CLUSTER_ID_SECRET="$2"; shift 2 ;;
    --grpc-addr)          GRPC_ADDR="$2"; shift 2 ;;
    --obi-profile)        OBI_PROFILE="$2"; shift 2 ;;
    --dynamic-sizing)     DYNAMIC_SIZING="true"; shift ;;
    --values-prefix)      VALUES_PREFIX="$2"; shift 2 ;;
    --chart-version)      CHART_VERSION="$2"; shift 2 ;;
    --upgrade-chart)      UPGRADE_CHART="true"; shift ;;
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

# Prefix a --set key with VALUES_PREFIX if set.
# Usage: setkey "agent.reliabilityMetrics.enabled=true"  →  "--set autoscaler.castai-kvisor.agent.reliabilityMetrics.enabled=true"
setkey() {
  local kv="$1"
  if [[ -n "$VALUES_PREFIX" ]]; then
    echo "--set ${VALUES_PREFIX}.${kv}"
  else
    echo "--set ${kv}"
  fi
}

run_cmd() {
  if [[ -n "$DRY_RUN" ]]; then
    printf "${YELLOW}[dry-run]${NC} %s\n" "$*"
  else
    # Use eval because $HELM_CTX/$KUBECTL_CTX must expand to multiple args or nothing.
    # Values containing shell metacharacters are single-quoted in build_creds_flags().
    eval "$@"
  fi
}

# Build helm flags for CAST AI credentials (fresh install only)
# Outputs flags to stdout — caller captures via $()
# Values are single-quoted to survive eval (handles $, spaces, backticks in API keys/paths).
build_creds_flags() {
  if [[ -n "$VALUES_FILE" ]]; then
    echo "-f '${VALUES_FILE//"'"/"'\\''"}'"
  fi

  # API key: inline value or pre-existing Secret ref
  if [[ -n "$API_KEY" ]]; then
    echo "--set 'castai.apiKey=${API_KEY//"'"/"'\\''"}'"
  elif [[ -n "$API_KEY_SECRET" ]]; then
    echo "--set 'castai.apiKeySecretRef=${API_KEY_SECRET//"'"/"'\\''"}'"
  fi

  # Cluster ID: inline value or pre-existing Secret ref
  if [[ -n "$CLUSTER_ID" ]]; then
    echo "--set 'castai.clusterID=${CLUSTER_ID//"'"/"'\\''"}'"
  elif [[ -n "$CLUSTER_ID_SECRET" ]]; then
    echo "--set 'castai.clusterIdSecretKeyRef.name=${CLUSTER_ID_SECRET//"'"/"'\\''"}'"
  fi

  # Optional gRPC address
  if [[ -n "$GRPC_ADDR" ]]; then
    echo "--set 'castai.grpcAddr=${GRPC_ADDR//"'"/"'\\''"}'"
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
CLUSTER_NAME="${CONTEXT:-$(kubectl config current-context 2>/dev/null || echo "unknown")}"
ok "Connected to cluster: $CLUSTER_NAME"

# ── eBPF compatibility check ────────────────────────────────────────────────
# OBI requires: Linux kernel ≥ 5.8 (ring buffers, BTF, bpf syscall), amd64 or arm64.
# We check all nodes via kubectl — no exec or debug pods needed.
step "eBPF Compatibility Check"

EBPF_ISSUES=0
NODE_DATA=$(kubectl $KUBECTL_CTX get nodes -o json 2>/dev/null) || {
  warn "Could not list nodes — skipping eBPF preflight check"
  NODE_DATA=""
}

if [[ -n "$NODE_DATA" ]]; then
  NODE_COUNT=$(echo "$NODE_DATA" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['items']))" 2>/dev/null || echo "0")

  # Check kernel versions and architecture for all nodes at once
  PREFLIGHT_RESULT=$(echo "$NODE_DATA" | python3 -c "
import sys, json, re

data = json.load(sys.stdin)
min_major, min_minor = 5, 8
bad_kernel = []
bad_arch = []
kernels = set()
arches = set()

for node in data['items']:
    name = node['metadata']['name']
    info = node['status'].get('nodeInfo', {})
    kernel = info.get('kernelVersion', 'unknown')
    arch = info.get('architecture', 'unknown')
    kernels.add(kernel)
    arches.add(arch)

    # Parse kernel version (e.g., '5.15.0-1034-gke', '6.1.75+')
    m = re.match(r'(\d+)\.(\d+)', kernel)
    if m:
        major, minor = int(m.group(1)), int(m.group(2))
        if (major, minor) < (min_major, min_minor):
            bad_kernel.append(f'{name} ({kernel})')
    else:
        bad_kernel.append(f'{name} (unparseable: {kernel})')

    if arch not in ('amd64', 'arm64'):
        bad_arch.append(f'{name} ({arch})')

print(f'NODES={len(data[\"items\"])}')
print(f'KERNELS={\" \".join(sorted(kernels))}')
print(f'ARCHES={\" \".join(sorted(arches))}')
print(f'BAD_KERNEL_COUNT={len(bad_kernel)}')
print(f'BAD_ARCH_COUNT={len(bad_arch)}')
for bk in bad_kernel:
    print(f'BAD_KERNEL={bk}')
for ba in bad_arch:
    print(f'BAD_ARCH={ba}')
" 2>/dev/null)

  if [[ -n "$PREFLIGHT_RESULT" ]]; then
    PREFLIGHT_NODES=""
    PREFLIGHT_KERNELS=""
    PREFLIGHT_ARCHES=""
    BAD_KERNEL_COUNT=0
    BAD_ARCH_COUNT=0
    BAD_KERNEL_LIST=""
    BAD_ARCH_LIST=""

    while IFS='=' read -r key val; do
      case "$key" in
        NODES)            PREFLIGHT_NODES="$val" ;;
        KERNELS)          PREFLIGHT_KERNELS="$val" ;;
        ARCHES)           PREFLIGHT_ARCHES="$val" ;;
        BAD_KERNEL_COUNT) BAD_KERNEL_COUNT="$val" ;;
        BAD_ARCH_COUNT)   BAD_ARCH_COUNT="$val" ;;
        BAD_KERNEL)       BAD_KERNEL_LIST="${BAD_KERNEL_LIST:+$BAD_KERNEL_LIST, }$val" ;;
        BAD_ARCH)         BAD_ARCH_LIST="${BAD_ARCH_LIST:+$BAD_ARCH_LIST, }$val" ;;
      esac
    done <<< "$PREFLIGHT_RESULT"

    info "Nodes: $PREFLIGHT_NODES | Kernels: $PREFLIGHT_KERNELS | Arch: $PREFLIGHT_ARCHES"

    if [[ "$BAD_KERNEL_COUNT" -gt 0 ]]; then
      err "Kernel < 5.8 detected on $BAD_KERNEL_COUNT node(s): $BAD_KERNEL_LIST"
      err "OBI requires Linux 5.8+ for eBPF ring buffers and BTF support."
      EBPF_ISSUES=1
    else
      ok "All nodes have kernel ≥ 5.8"
    fi

    if [[ "$BAD_ARCH_COUNT" -gt 0 ]]; then
      err "Unsupported architecture on $BAD_ARCH_COUNT node(s): $BAD_ARCH_LIST"
      err "OBI supports amd64 and arm64 only."
      EBPF_ISSUES=1
    else
      ok "All nodes use supported architecture ($PREFLIGHT_ARCHES)"
    fi
  else
    warn "Could not parse node info — skipping eBPF preflight check"
  fi

  if [[ "$EBPF_ISSUES" -gt 0 ]]; then
    err "eBPF preflight check failed. OBI may not work on the affected nodes."
    err "Proceed anyway? [y/N]"
    if [[ -z "$DRY_RUN" ]]; then
      read -r REPLY
      if [[ ! "$REPLY" =~ ^[Yy]$ ]]; then
        err "Aborted."
        exit 1
      fi
      warn "Proceeding despite eBPF compatibility issues"
    fi
  fi
fi

# ── Helm repo ───────────────────────────────────────────────────────────────
if [[ -z "$SKIP_REPO" ]]; then
  step "Helm Repository"
  run_cmd "helm repo add castai-helm https://castai.github.io/helm-charts 2>/dev/null || true"
  run_cmd "helm repo update castai-helm"
  ok "Helm repo up to date"
fi

# ── Auto-detect installation type ────────────────────────────────────────────
# When the user hasn't explicitly set --release or --chart, scan for an existing
# kvisor release to determine if it was installed standalone or via the umbrella chart.
if [[ -z "$USER_SET_RELEASE" ]]; then
  step "Auto-detecting Installation Type"

  # Get all releases in the namespace as JSON and detect kvisor's installation method.
  # Chart column tells us: "castai-kvisor-1.x.x" = standalone, "castai-0.x.x" = umbrella.
  DETECTED=$(helm $HELM_CTX list -n "$NAMESPACE" -o json 2>/dev/null | python3 -c "
import sys, json, re

releases = json.load(sys.stdin)
for r in releases:
    chart = r.get('chart', '')
    name = r.get('name', '')
    # Standalone: chart starts with 'castai-kvisor-'
    if chart.startswith('castai-kvisor-'):
        print(f'TYPE=standalone')
        print(f'RELEASE={name}')
        print(f'CHART_NAME={chart}')
        sys.exit(0)

for r in releases:
    chart = r.get('chart', '')
    name = r.get('name', '')
    # Umbrella: chart is 'castai-X.Y.Z' (version directly after 'castai-')
    if re.match(r'^castai-\d+\.\d+\.\d+', chart):
        print(f'TYPE=umbrella')
        print(f'RELEASE={name}')
        print(f'CHART_NAME={chart}')
        sys.exit(0)

print('TYPE=none')
" 2>/dev/null) || DETECTED="TYPE=none"

  DETECTED_TYPE=""
  DETECTED_RELEASE=""
  DETECTED_CHART_NAME=""
  while IFS='=' read -r key val; do
    case "$key" in
      TYPE)       DETECTED_TYPE="$val" ;;
      RELEASE)    DETECTED_RELEASE="$val" ;;
      CHART_NAME) DETECTED_CHART_NAME="$val" ;;
    esac
  done <<< "$DETECTED"

  case "$DETECTED_TYPE" in
    standalone)
      RELEASE="$DETECTED_RELEASE"
      if [[ -z "$USER_SET_CHART" ]]; then
        CHART="castai-helm/castai-kvisor"
      fi
      ok "Detected standalone kvisor (release: $RELEASE, chart: $DETECTED_CHART_NAME)"
      ;;
    umbrella)
      RELEASE="$DETECTED_RELEASE"
      if [[ -z "$USER_SET_CHART" ]]; then
        CHART="castai-helm/castai"
      fi
      if [[ -z "$VALUES_PREFIX" ]]; then
        # Discover the values path to castai-kvisor by inspecting the release's current values.
        # The umbrella chart nests kvisor under an intermediate subchart (e.g. autoscaler.castai-kvisor).
        # We walk the YAML tree to find the path containing a 'castai-kvisor' key with kvisor-like children.
        VALUES_PREFIX=$(helm $HELM_CTX get values "$DETECTED_RELEASE" -n "$NAMESPACE" -o json 2>/dev/null | python3 -c "
import sys, json

def find_kvisor_path(obj, path=''):
    \"\"\"Recursively find the path to a 'castai-kvisor' key that has dict children (agent, controller, etc).\"\"\"
    if not isinstance(obj, dict):
        return None
    for key, val in obj.items():
        current = f'{path}.{key}' if path else key
        if key == 'castai-kvisor' and isinstance(val, dict):
            # Verify it looks like real kvisor config (has agent/controller/castai keys)
            kvisor_keys = set(val.keys())
            if kvisor_keys & {'agent', 'controller', 'castai', 'enabled'}:
                return current
        result = find_kvisor_path(val, current)
        if result:
            return result
    return None

data = json.load(sys.stdin)
path = find_kvisor_path(data)
if path:
    print(path)
else:
    # Fallback: try common known paths
    print('castai-kvisor')
" 2>/dev/null) || VALUES_PREFIX="castai-kvisor"
      fi
      ok "Detected umbrella chart (release: $RELEASE, chart: $DETECTED_CHART_NAME)"
      info "Auto-configured: --release $RELEASE --chart $CHART --values-prefix $VALUES_PREFIX"
      ;;
    *)
      info "No existing CAST AI release found in namespace '$NAMESPACE' — using defaults"
      ;;
  esac
fi

# ── Check existing release ──────────────────────────────────────────────────
step "Checking Existing Release"

if helm $HELM_CTX status "$RELEASE" -n "$NAMESPACE" >/dev/null 2>&1; then
  CURRENT_REVISION=$(helm $HELM_CTX history "$RELEASE" -n "$NAMESPACE" --max 1 -o json 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['revision'])" 2>/dev/null || echo "?")
  ok "Release '$RELEASE' found (revision $CURRENT_REVISION) — upgrade mode"

  # Auto-detect chart version to pin upgrades (avoid bumping unrelated components).
  # --upgrade-chart skips pinning; --chart-version overrides detection.
  if [[ -z "$UPGRADE_CHART" && -z "$CHART_VERSION" ]]; then
    CHART_VERSION=$(helm $HELM_CTX history "$RELEASE" -n "$NAMESPACE" --max 1 -o json 2>/dev/null | python3 -c "
import sys, json, re
entry = json.load(sys.stdin)[0]
chart = entry.get('chart', '')
# Extract version from chart string like 'castai-0.33.21' or 'castai-kvisor-1.0.117'
m = re.match(r'.*?-(\d+\.\d+\.\d+.*)$', chart)
if m:
    print(m.group(1))
" 2>/dev/null) || CHART_VERSION=""
    if [[ -n "$CHART_VERSION" ]]; then
      info "Pinning chart version to $CHART_VERSION (use --upgrade-chart for latest)"
    fi
  fi
  if [[ -n "$UPGRADE_CHART" ]]; then
    info "Upgrading to latest chart version (--upgrade-chart)"
  fi

  # Auto-detect which Secret holds the CAST AI API key.
  # Standalone kvisor creates "castai-kvisor"; the umbrella chart creates "castai-credentials".
  # The ch-exporter subchart defaults to "castai-kvisor", so we must override when different.
  DETECTED_API_KEY_SECRET=""
  for candidate in castai-kvisor castai-credentials; do
    if kubectl $KUBECTL_CTX get secret "$candidate" -n "$NAMESPACE" >/dev/null 2>&1; then
      DETECTED_API_KEY_SECRET="$candidate"
      break
    fi
  done
  if [[ -n "$DETECTED_API_KEY_SECRET" ]]; then
    info "Detected API key secret: $DETECTED_API_KEY_SECRET"
  else
    warn "Could not detect API key secret — ch-exporter will use chart default (castai-kvisor)"
  fi
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

# ── Build version flag ───────────────────────────────────────────────────────
HELM_VERSION_FLAG=""
if [[ -n "$CHART_VERSION" ]]; then
  HELM_VERSION_FLAG="--version $CHART_VERSION"
fi

# ── Phase 1: CRD Detection & Operator Bootstrap ─────────────────────────────
step "Phase 1: ClickHouse Operator CRD Check"

CRD_EXISTS=""
OPERATOR_RUNNING=""
if kubectl $KUBECTL_CTX get crd clickhouseinstallations.clickhouse.altinity.com >/dev/null 2>&1; then
  CRD_EXISTS="true"
  # CRD exists — but check if the operator is actually running.
  # It may have been deleted (e.g. after a failed install cleanup) while the CRD remained.
  if kubectl $KUBECTL_CTX get pods -n "$NAMESPACE" -l app=clickhouse-operator --field-selector=status.phase=Running 2>/dev/null | grep -q clickhouse-operator; then
    OPERATOR_RUNNING="true"
    ok "ClickHouseInstallation CRD already exists and operator is running — skipping operator install"
  else
    warn "ClickHouseInstallation CRD exists but operator is not running — will install operator"
  fi
fi

if [[ -n "$OPERATOR_RUNNING" ]]; then
  : # nothing to do
elif [[ -n "$CRD_EXISTS" ]]; then
  # CRD present but operator missing — run Phase 1 to reinstall the operator
  info "Reinstalling ClickHouse operator (CRD already registered, skipping CRD wait)..."

  PHASE1_CMD="helm upgrade --install $RELEASE $CHART \\
    -n $NAMESPACE --create-namespace \\
    $HELM_CTX $HELM_VERSION_FLAG"

  if [[ -n "$INSTALL_MODE" ]]; then
    PHASE1_CMD="$PHASE1_CMD $(build_creds_flags)"
  else
    PHASE1_CMD="$PHASE1_CMD \\
    --reset-then-reuse-values"
    if [[ -n "$VALUES_FILE" ]]; then
      PHASE1_CMD="$PHASE1_CMD -f '${VALUES_FILE//"'"/"'\\''"}'"
    fi
  fi

  PHASE1_CMD="$PHASE1_CMD \\
    $(setkey reliabilityMetrics.enabled=true) \\
    $(setkey reliabilityMetrics.operator.enabled=true) \\
    $(setkey reliabilityMetrics.install.enabled=false) \\
    $(setkey reliabilityMetrics.exporter.enabled=false)"

  run_cmd "$PHASE1_CMD"

  if [[ -z "$DRY_RUN" ]]; then
    info "Waiting for operator pod to be ready..."
    kubectl $KUBECTL_CTX rollout status deployment -n "$NAMESPACE" -l app=clickhouse-operator --timeout=60s 2>/dev/null || true
    ok "ClickHouse operator ready"
  fi
else
  warn "ClickHouseInstallation CRD not found"
  info "Installing ClickHouse operator first (Phase 1)..."
  info "This deploys ONLY the operator + CRD, without enabling the full stack."

  # Phase 1: Install just the operator to register the CRD.
  # We explicitly disable install.enabled so the ClickHouseInstallation CR isn't created yet.
  PHASE1_CMD="helm upgrade --install $RELEASE $CHART \\
    -n $NAMESPACE --create-namespace \\
    $HELM_CTX $HELM_VERSION_FLAG"

  # Fresh installs need credentials; upgrades reuse existing values
  if [[ -n "$INSTALL_MODE" ]]; then
    PHASE1_CMD="$PHASE1_CMD $(build_creds_flags)"
  else
    PHASE1_CMD="$PHASE1_CMD \\
    --reset-then-reuse-values"
    # Layer -f values on top of reused values (allows overriding openPorts, env, etc.)
    if [[ -n "$VALUES_FILE" ]]; then
      PHASE1_CMD="$PHASE1_CMD -f '${VALUES_FILE//"'"/"'\\''"}'"
    fi
  fi

  PHASE1_CMD="$PHASE1_CMD \\
    $(setkey reliabilityMetrics.enabled=true) \\
    $(setkey reliabilityMetrics.operator.enabled=true) \\
    $(setkey reliabilityMetrics.install.enabled=false) \\
    $(setkey reliabilityMetrics.exporter.enabled=false)"

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
  $HELM_CTX $HELM_VERSION_FLAG"

# Fresh installs need credentials; upgrades reuse existing values
if [[ -n "$INSTALL_MODE" ]]; then
  HELM_CMD="$HELM_CMD $(build_creds_flags)"
else
  HELM_CMD="$HELM_CMD \\
  --reset-then-reuse-values"
  # Layer -f values on top of reused values (allows overriding openPorts, env, etc.)
  if [[ -n "$VALUES_FILE" ]]; then
    HELM_CMD="$HELM_CMD -f '${VALUES_FILE//"'"/"'\\''"}'"
  fi
fi

HELM_CMD="$HELM_CMD \\
  $(setkey agent.reliabilityMetrics.enabled=true) \\
  $(setkey agent.reliabilityMetrics.obi.sizingProfile=$OBI_PROFILE) \\
  $(setkey agent.reliabilityMetrics.obi.dynamicSizing=$DYNAMIC_SIZING) \\
  $(setkey controller.reliabilityMetrics.enabled=true) \\
  $(setkey reliabilityMetrics.enabled=true) \\
  $(setkey reliabilityMetrics.install.enabled=true) \\
  $(setkey reliabilityMetrics.exporter.enabled=true)"

# Override the ch-exporter API key secret ref if we detected a non-default secret
if [[ -z "$INSTALL_MODE" && -n "$DETECTED_API_KEY_SECRET" && "$DETECTED_API_KEY_SECRET" != "castai-kvisor" ]]; then
  HELM_CMD="$HELM_CMD \\
  $(setkey reliabilityMetrics.castai.apiKeySecretRef=$DETECTED_API_KEY_SECRET)"
  info "Overriding ch-exporter apiKeySecretRef → $DETECTED_API_KEY_SECRET"
fi

# Under an umbrella chart the ClickHouse service is named <release>-clickhouse (e.g. castai-clickhouse)
# rather than the standalone default castai-kvisor-clickhouse. Override the collector ClickHouse
# address when the release name differs from the standalone default (castai-kvisor).
if [[ "$RELEASE" != "castai-kvisor" ]]; then
  CH_ADDR="tcp://${RELEASE}-clickhouse.${NAMESPACE}.svc.cluster.local:9000"
  HELM_CMD="$HELM_CMD \\
  $(setkey agent.reliabilityMetrics.collector.clickhouseExporter.address=$CH_ADDR) \\
  $(setkey controller.reliabilityMetrics.collector.clickhouseExporter.address=$CH_ADDR)"
  info "Overriding ClickHouse address → $CH_ADDR"
fi

# Only skip installing our operator if an external one was already running before we started.
# If we installed it in Phase 1 (either CRD was missing, or CRD existed but operator wasn't running),
# we need operator.enabled=true so it stays managed by this release.
if [[ -n "$OPERATOR_RUNNING" ]]; then
  HELM_CMD="$HELM_CMD \\
  $(setkey reliabilityMetrics.operator.enabled=false)"
  info "Using existing ClickHouse operator (not installing chart's operator)"
else
  HELM_CMD="$HELM_CMD \\
  $(setkey reliabilityMetrics.operator.enabled=true)"
  info "ClickHouse operator enabled (installed in Phase 1)"
fi

info "OBI sizing profile: $OBI_PROFILE"
info "Dynamic sizing: $DYNAMIC_SIZING"
echo ""

run_cmd "$HELM_CMD"

# ── Phase 3: Verify Rollout ──────────────────────────────────────────────────
if [[ -z "$DRY_RUN" ]]; then
  step "Phase 3: Verifying Rollout"

  # Under an umbrella chart the release name is used as a helm instance label prefix,
  # e.g. release=castai → daemonset castai-castai-kvisor-agent.
  # Under a standalone chart, release=castai-kvisor → daemonset castai-kvisor-agent.
  # Derive the resource name prefix: if VALUES_PREFIX is set we're in umbrella mode.
  if [[ -n "$VALUES_PREFIX" ]]; then
    AGENT_DS="${RELEASE}-castai-kvisor-agent"
    AGENT_LABEL="app.kubernetes.io/name=castai-kvisor-agent"
  else
    AGENT_DS="${RELEASE}-agent"
    AGENT_LABEL="app.kubernetes.io/name=${RELEASE}-agent"
  fi

  info "Waiting for agent DaemonSet rollout..."
  kubectl $KUBECTL_CTX rollout status daemonset/${AGENT_DS} -n "$NAMESPACE" --timeout=120s 2>/dev/null || {
    warn "DaemonSet rollout not complete within 120s. Check pods:"
    kubectl $KUBECTL_CTX get pods -n "$NAMESPACE" -l "$AGENT_LABEL"
  }

  echo ""
  info "Pod status:"
  kubectl $KUBECTL_CTX get pods -n "$NAMESPACE" 2>/dev/null | grep -E "kvisor|clickhouse"

  echo ""
  AGENT_PODS=$(kubectl $KUBECTL_CTX get pods -n "$NAMESPACE" -l "$AGENT_LABEL" -o name 2>/dev/null | head -1)
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
