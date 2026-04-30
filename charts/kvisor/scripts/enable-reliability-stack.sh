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
#       --storage-class     StorageClass for ClickHouse PVC (e.g. gp3, premium-rwo).
#                           Overrides the cluster default. Useful when no default
#                           StorageClass is set (common on EKS 1.33+)
#       --cluster-proxy     Also enable the kvisor cluster proxy feature
#       --print-only        Print the final helm commands and exit (no preflight,
#                           no auto-detection from cluster — uses defaults/flags only)
#       --dry-run           Print commands without executing
#       --skip-repo         Skip helm repo add/update
#   -v, --verbose           Show detailed diagnostic output (helm commands,
#                           pod status, operator logs on failure)
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
CLUSTER_ID_CONFIGMAP=""
GRPC_ADDR=""
OBI_PROFILE="auto"
DYNAMIC_SIZING="false"
VALUES_PREFIX=""
CHART_VERSION=""
UPGRADE_CHART=""
STORAGE_CLASS=""
CLUSTER_PROXY=""
PRINT_ONLY=""
DRY_RUN=""
SKIP_REPO=""
VERBOSE=""
INSTALL_MODE=""
USER_SET_RELEASE=""
USER_SET_CHART=""
DETECTED_API_KEY_SECRET=""
CRD_EXISTS=""
OPERATOR_RUNNING=""
OPERATOR_NS=""
OPERATOR_WATCH_WARNING=""

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
debug() { [[ -n "$VERBOSE" ]] && printf "${CYAN}   [debug]${NC} %s\n" "$*" || true; }

# Print a command inside a clearly delimited block for copy-pasting.
# Usage: print_cmd_block "label" "command string"
print_cmd_block() {
  local label="$1" cmd="$2"
  printf "\n${BOLD}${GREEN}▶ %s${NC}\n" "$label"
  printf "${CYAN}┌─────────────────────────────────────────────────────────────────${NC}\n"
  while IFS= read -r line; do
    printf "${CYAN}│${NC} %s\n" "$line"
  done <<< "$cmd"
  printf "${CYAN}└─────────────────────────────────────────────────────────────────${NC}\n"
}

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
    --storage-class)      STORAGE_CLASS="$2"; shift 2 ;;
    --cluster-proxy)      CLUSTER_PROXY="true"; shift ;;
    --print-only)         PRINT_ONLY="true"; DRY_RUN="true"; shift ;;
    --dry-run)            DRY_RUN="true"; shift ;;
    --skip-repo)          SKIP_REPO="true"; shift ;;
    -v|--verbose)         VERBOSE="true"; shift ;;
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
  if [[ -n "$PRINT_ONLY" ]]; then
    printf "%s\n" "$*"
  elif [[ -n "$DRY_RUN" ]]; then
    printf "${YELLOW}[dry-run]${NC} %s\n" "$*"
  else
    if [[ -n "$VERBOSE" ]]; then
      printf "\n${CYAN}   [cmd]${NC} %s\n\n" "$*"
    fi
    # Use eval because $HELM_CTX/$KUBECTL_CTX must expand to multiple args or nothing.
    # Values containing shell metacharacters are single-quoted in build_creds_flags().
    eval "$@"
  fi
}

# Detect ClickHouse operator across all namespaces and verify it watches our target namespace.
# Sets: OPERATOR_RUNNING="true" if operator is running AND watches NAMESPACE.
#        OPERATOR_NS (namespace where operator was found)
#        OPERATOR_WATCH_WARNING (set if operator runs but doesn't watch our namespace)
detect_operator() {
  OPERATOR_NS=""
  OPERATOR_WATCH_WARNING=""

  # Find the clickhouse-operator deployment across all namespaces.
  # Different installation methods use different labels, so we search by multiple strategies:
  #   1. Label: clickhouse.altinity.com/app=chop (Altinity's own label, most reliable)
  #   2. Label: app=clickhouse-operator (older Altinity Helm chart)
  #   3. Label: app.kubernetes.io/name contains clickhouse-operator (convention, may include version suffix)
  local deploy_info=""
  for label in "clickhouse.altinity.com/app=chop" "app=clickhouse-operator"; do
    deploy_info=$(kubectl $KUBECTL_CTX get deployments --all-namespaces -l "$label" \
      -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\n"}{end}' 2>/dev/null) || true
    if [[ -n "$deploy_info" ]]; then
      break
    fi
  done

  # Fallback: search by deployment name containing "clickhouse-operator" (not just "clickhouse")
  if [[ -z "$deploy_info" ]]; then
    deploy_info=$(kubectl $KUBECTL_CTX get deployments --all-namespaces \
      -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\n"}{end}' 2>/dev/null \
      | grep "clickhouse-operator" || true)
  fi

  if [[ -z "$deploy_info" ]]; then
    debug "No clickhouse-operator deployment found in any namespace"
    return 1
  fi

  # Take the first match
  OPERATOR_NS=$(echo "$deploy_info" | head -1 | cut -f1)
  debug "Found operator deployment: $(echo "$deploy_info" | head -1)"
  local deploy_name
  deploy_name=$(echo "$deploy_info" | head -1 | cut -f2)

  # Verify the deployment has running pods
  local ready_replicas
  ready_replicas=$(kubectl $KUBECTL_CTX get deployment "$deploy_name" -n "$OPERATOR_NS" \
    -o jsonpath='{.status.readyReplicas}' 2>/dev/null) || ready_replicas="0"
  debug "Operator deployment '$deploy_name' in '$OPERATOR_NS': readyReplicas=${ready_replicas:-0}"
  if [[ "${ready_replicas:-0}" -lt 1 ]]; then
    debug "Operator not ready (readyReplicas < 1)"
    return 1
  fi

  # Check if the operator watches our namespace.
  # WATCH_NAMESPACES env var: empty = all namespaces, comma-separated list = specific namespaces.
  local watch_ns
  watch_ns=$(kubectl $KUBECTL_CTX get deployment "$deploy_name" -n "$OPERATOR_NS" \
    -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="WATCH_NAMESPACES")].value}' 2>/dev/null) || watch_ns=""

  debug "Operator WATCH_NAMESPACES='${watch_ns:-<empty, watches all>}'"
  if [[ -z "$watch_ns" ]]; then
    # Empty WATCH_NAMESPACES = watches all namespaces
    OPERATOR_RUNNING="true"
  elif echo ",$watch_ns," | grep -q ",$NAMESPACE,"; then
    # Our namespace is in the watch list
    OPERATOR_RUNNING="true"
  else
    # Operator runs but doesn't watch our namespace
    OPERATOR_WATCH_WARNING="true"
  fi
}

# Build the base "helm upgrade --install" prefix with optional context and version flags.
# Avoids blank continuation lines when HELM_CTX or HELM_VERSION_FLAG are empty.
build_helm_base() {
  local cmd="helm upgrade --install $RELEASE $CHART \\
  -n $NAMESPACE --create-namespace"
  if [[ -n "$HELM_CTX" ]]; then
    cmd="$cmd \\
  $HELM_CTX"
  fi
  if [[ -n "$HELM_VERSION_FLAG" ]]; then
    cmd="$cmd \\
  $HELM_VERSION_FLAG"
  fi
  echo "$cmd"
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

  # Cluster ID: inline value, pre-existing Secret ref, or pre-existing ConfigMap ref
  if [[ -n "$CLUSTER_ID" ]]; then
    echo "--set 'castai.clusterID=${CLUSTER_ID//"'"/"'\\''"}'"
  elif [[ -n "$CLUSTER_ID_SECRET" ]]; then
    echo "--set 'castai.clusterIdSecretKeyRef.name=${CLUSTER_ID_SECRET//"'"/"'\\''"}'"
  elif [[ -n "$CLUSTER_ID_CONFIGMAP" ]]; then
    echo "--set 'castai.clusterIdConfigMapKeyRef.name=${CLUSTER_ID_CONFIGMAP//"'"/"'\\''"}'"
  fi

  # Optional gRPC address
  if [[ -n "$GRPC_ADDR" ]]; then
    echo "--set 'castai.grpcAddr=${GRPC_ADDR//"'"/"'\\''"}'"
  fi
}

# ── Print-only mode: skip all cluster interaction ────────────────────────────
# In --print-only mode we skip preflight, auto-detection, Phase 1, and OBI sizing.
# The user must provide --release, --chart, --values-prefix if not using defaults.
# If credentials are supplied via flags, assume fresh install mode.
if [[ -n "$PRINT_ONLY" ]]; then
  HAS_CREDS=""
  [[ -n "$VALUES_FILE" ]] && HAS_CREDS="true"
  [[ -n "$API_KEY" || -n "$API_KEY_SECRET" ]] && [[ -n "$CLUSTER_ID" || -n "$CLUSTER_ID_SECRET" || -n "$CLUSTER_ID_CONFIGMAP" ]] && HAS_CREDS="true"
  if [[ -n "$HAS_CREDS" ]]; then
    INSTALL_MODE="true"
  fi
fi

if [[ -z "$PRINT_ONLY" ]]; then

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

# ── StorageClass check ──────────────────────────────────────────────────────
# ClickHouse PVCs don't specify a storageClassName — they rely on a default.
# EKS 1.33+ creates gp2 but doesn't mark it as default, causing silent PVC Pending.
step "StorageClass Check"
DEFAULT_SC=$(kubectl $KUBECTL_CTX get sc -o jsonpath='{range .items[?(@.metadata.annotations.storageclass\.kubernetes\.io/is-default-class=="true")]}{.metadata.name}{"\n"}{end}' 2>/dev/null) || DEFAULT_SC=""
if [[ -n "$STORAGE_CLASS" ]]; then
  ok "StorageClass override: $STORAGE_CLASS (via --storage-class)"
elif [[ -z "$DEFAULT_SC" ]]; then
  warn "No default StorageClass found!"
  warn "ClickHouse requires a default StorageClass for its PersistentVolumeClaim."
  warn "Without one, the ClickHouse pod will stay Pending indefinitely."
  echo ""
  info "Option 1: Re-run with --storage-class <name> to target a specific StorageClass"
  info "Option 2: Mark an existing StorageClass as default:"
  # Check if gp2 exists (common on EKS) and suggest marking it as default
  if kubectl $KUBECTL_CTX get sc gp2 >/dev/null 2>&1; then
    info "  kubectl annotate storageclass gp2 storageclass.kubernetes.io/is-default-class=true"
  elif kubectl $KUBECTL_CTX get sc gp3 >/dev/null 2>&1; then
    info "  kubectl annotate storageclass gp3 storageclass.kubernetes.io/is-default-class=true"
  else
    SC_LIST=$(kubectl $KUBECTL_CTX get sc -o jsonpath='{.items[*].metadata.name}' 2>/dev/null) || SC_LIST=""
    if [[ -n "$SC_LIST" ]]; then
      info "Available StorageClasses: $SC_LIST"
      info "  kubectl annotate storageclass <name> storageclass.kubernetes.io/is-default-class=true"
    else
      warn "No StorageClasses found at all — install a CSI driver (e.g. EBS CSI for EKS)"
    fi
  fi
  echo ""
  if [[ -z "$DRY_RUN" ]]; then
    err "Proceed without a default StorageClass? [y/N]"
    read -r REPLY
    if [[ ! "$REPLY" =~ ^[Yy]$ ]]; then
      err "Aborted. Set a default StorageClass and re-run."
      exit 1
    fi
    warn "Proceeding without default StorageClass — ClickHouse PVC may stay Pending"
  fi
else
  ok "Default StorageClass: $DEFAULT_SC"
fi

# ── CSI driver check ──────────────────────────────────────────────────────
# On EKS 1.31+, the in-tree kubernetes.io/aws-ebs provisioner is transparently
# redirected to ebs.csi.aws.com via CSI migration. If the EBS CSI driver isn't
# installed, PVCs silently stay Pending. Check that the CSI driver backing the
# selected StorageClass actually has running pods.
SELECTED_SC="${STORAGE_CLASS:-$DEFAULT_SC}"
if [[ -n "$SELECTED_SC" ]]; then
  SC_PROVISIONER=$(kubectl $KUBECTL_CTX get sc "$SELECTED_SC" -o jsonpath='{.provisioner}' 2>/dev/null) || SC_PROVISIONER=""
  if [[ -n "$SC_PROVISIONER" ]]; then
    # Map in-tree provisioners to their CSI migration targets
    CSI_DRIVER=""
    case "$SC_PROVISIONER" in
      kubernetes.io/aws-ebs)    CSI_DRIVER="ebs.csi.aws.com" ;;
      kubernetes.io/gce-pd)     CSI_DRIVER="pd.csi.storage.gke.io" ;;
      kubernetes.io/azure-disk) CSI_DRIVER="disk.csi.azure.com" ;;
      ebs.csi.aws.com|pd.csi.storage.gke.io|disk.csi.azure.com)
        CSI_DRIVER="$SC_PROVISIONER" ;;
    esac

    if [[ -n "$CSI_DRIVER" ]]; then
      # Check if the CSI driver is registered
      if kubectl $KUBECTL_CTX get csidrivers "$CSI_DRIVER" >/dev/null 2>&1; then
        debug "CSI driver '$CSI_DRIVER' is registered"

        # On EKS, the EBS CSI driver may be registered but crashing due to missing IAM permissions.
        # The driver needs AmazonEBSCSIDriverPolicy attached to the node role or via IRSA.
        # Check controller pod health to catch this early.
        CSI_HEALTHY="true"
        if [[ "$CSI_DRIVER" == "ebs.csi.aws.com" ]]; then
          CSI_PROBLEM_PODS=$(kubectl $KUBECTL_CTX get pods -n kube-system -l app=ebs-csi-controller \
            -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.phase}{"\t"}{range .status.containerStatuses[*]}{.state.waiting.reason}{" "}{end}{"\n"}{end}' 2>/dev/null) || CSI_PROBLEM_PODS=""

          if [[ -n "$CSI_PROBLEM_PODS" ]]; then
            # Check for CrashLoopBackOff or other non-Running states
            CSI_CRASH=$(echo "$CSI_PROBLEM_PODS" | grep -iE "CrashLoopBackOff|Error|ImagePullBackOff|CreateContainerConfigError" || true)
            CSI_NOT_READY=$(echo "$CSI_PROBLEM_PODS" | grep -v "Running" | grep -v "^$" || true)

            if [[ -n "$CSI_CRASH" ]]; then
              CSI_HEALTHY=""
              warn "EBS CSI driver pods are crashing!"
              while IFS=$'\t' read -r pod_name pod_phase pod_reasons; do
                [[ -z "$pod_name" ]] && continue
                warn "  $pod_name: $pod_phase ${pod_reasons:+($pod_reasons)}"
              done <<< "$CSI_CRASH"
              echo ""
              warn "This is usually caused by missing IAM permissions."
              warn "The EBS CSI controller needs the AmazonEBSCSIDriverPolicy."
              echo ""
              info "Fix Option 1 — Attach policy to node instance role (simplest):"
              info "  # Find the node role name:"
              info "  NG=\$(aws eks list-nodegroups --cluster-name <cluster> --region <region> --query 'nodegroups[0]' --output text)"
              info "  NODE_ROLE=\$(aws eks describe-nodegroup --cluster-name <cluster> --region <region> --nodegroup-name \$NG --query 'nodegroup.nodeRole' --output text | xargs basename)"
              info "  aws iam attach-role-policy --role-name \$NODE_ROLE --policy-arn arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
              echo ""
              info "Fix Option 2 — Use IRSA (recommended for production, requires OIDC provider):"
              info "  # Step 1: Ensure OIDC provider exists (one-time per cluster):"
              info "  eksctl utils associate-iam-oidc-provider --region <region> --cluster <cluster> --approve"
              info "  # Step 2: Create the service account with IAM role:"
              info "  eksctl create iamserviceaccount --name ebs-csi-controller-sa --namespace kube-system \\"
              info "    --cluster <cluster> --region <region> --role-name AmazonEKS_EBS_CSI_DriverRole \\"
              info "    --attach-policy-arn arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy --approve"
              echo ""
              info "After attaching the policy, restart the CSI controller:"
              info "  kubectl rollout restart deployment ebs-csi-controller -n kube-system"
              echo ""
            elif [[ -n "$CSI_NOT_READY" ]]; then
              debug "EBS CSI controller pods not fully ready (may still be starting)"
            fi
          else
            debug "No EBS CSI controller pods found — driver may not be fully deployed"
          fi
        fi

        if [[ -n "$CSI_HEALTHY" ]]; then
          ok "CSI driver: $CSI_DRIVER"
        else
          if [[ -z "$DRY_RUN" ]]; then
            err "Proceed with unhealthy CSI driver? [y/N]"
            read -r REPLY
            if [[ ! "$REPLY" =~ ^[Yy]$ ]]; then
              err "Aborted. Fix the CSI driver IAM permissions and re-run."
              exit 1
            fi
            warn "Proceeding with unhealthy CSI driver — ClickHouse PVC will likely stay Pending"
          fi
        fi
      else
        warn "CSI driver '$CSI_DRIVER' is not installed!"
        warn "StorageClass '$SELECTED_SC' uses provisioner '$SC_PROVISIONER',"
        warn "which requires the '$CSI_DRIVER' CSI driver to provision volumes."
        warn "Without it, ClickHouse PVC will stay Pending indefinitely."
        echo ""
        if [[ "$CSI_DRIVER" == "ebs.csi.aws.com" ]]; then
          info "Step 1 — Install the EBS CSI driver addon:"
          info "  eksctl create addon --name aws-ebs-csi-driver --cluster <cluster> --region <region>"
          info "  Or: EKS Console → Cluster → Add-ons → Amazon EBS CSI Driver"
          echo ""
          info "Step 2 — Grant IAM permissions (simplest: attach to node role):"
          info "  NG=\$(aws eks list-nodegroups --cluster-name <cluster> --region <region> --query 'nodegroups[0]' --output text)"
          info "  NODE_ROLE=\$(aws eks describe-nodegroup --cluster-name <cluster> --region <region> --nodegroup-name \$NG --query 'nodegroup.nodeRole' --output text | xargs basename)"
          info "  aws iam attach-role-policy --role-name \$NODE_ROLE --policy-arn arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
          echo ""
          info "For production, use IRSA instead (requires OIDC provider — see AWS EKS docs)"
        fi
        echo ""
        if [[ -z "$DRY_RUN" ]]; then
          err "Proceed without CSI driver? [y/N]"
          read -r REPLY
          if [[ ! "$REPLY" =~ ^[Yy]$ ]]; then
            err "Aborted. Install the CSI driver and re-run."
            exit 1
          fi
          warn "Proceeding without CSI driver — ClickHouse PVC will likely stay Pending"
        fi
      fi
    else
      debug "Provisioner '$SC_PROVISIONER' — not a known CSI migration target, skipping driver check"
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

  debug "Detection result: $DETECTED"
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
        VALUES_PREFIX=$(helm $HELM_CTX get values -a "$DETECTED_RELEASE" -n "$NAMESPACE" -o json 2>/dev/null | python3 -c "
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

debug "Checking helm release: helm status '$RELEASE' -n '$NAMESPACE'"
if helm $HELM_CTX status "$RELEASE" -n "$NAMESPACE" >/dev/null 2>&1; then
  CURRENT_REVISION=$(helm $HELM_CTX history "$RELEASE" -n "$NAMESPACE" --max 1 -o json 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['revision'])" 2>/dev/null || echo "?")
  ok "Release '$RELEASE' found (revision $CURRENT_REVISION) — upgrade mode"
  debug "Install mode: UPGRADE (existing release found)"

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

  # Detect deployed kvisor version from running pod image tag.
  # The pod label varies by install type:
  #   Standalone: app.kubernetes.io/name=castai-kvisor-agent
  #   Umbrella:   app.kubernetes.io/name=castai-castai-kvisor-agent (release-chartname-agent)
  # We search by component label which is consistent across both.
  DEPLOYED_KVISOR_VERSION=""
  KVISOR_IMAGE=$(kubectl $KUBECTL_CTX get pods -n "$NAMESPACE" \
    -l app.kubernetes.io/component=agent -o jsonpath='{.items[0].spec.containers[?(@.name=="kvisor")].image}' 2>/dev/null) || KVISOR_IMAGE=""
  # Fallback: try by name substring (covers non-standard labels)
  if [[ -z "$KVISOR_IMAGE" ]]; then
    KVISOR_IMAGE=$(kubectl $KUBECTL_CTX get pods -n "$NAMESPACE" -o json 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
for pod in data.get('items', []):
    name = pod['metadata']['name']
    if 'kvisor' not in name or 'agent' not in name:
        continue
    for c in pod['spec']['containers']:
        if c['name'] == 'kvisor':
            print(c['image'])
            sys.exit(0)
" 2>/dev/null) || KVISOR_IMAGE=""
  fi
  if [[ -n "$KVISOR_IMAGE" ]]; then
    DEPLOYED_KVISOR_VERSION="${KVISOR_IMAGE##*:}"
  fi

  # Extract the kvisor appVersion bundled in a chart package.
  # Works for both umbrella (kvisor nested under autoscaler) and standalone charts.
  # Usage: kvisor_version_in_chart <chart-ref> [--version X.Y.Z]
  kvisor_version_in_chart() {
    local tmpdir
    tmpdir=$(mktemp -d) || return 1
    if helm pull "$@" --untar --untardir "$tmpdir" 2>/dev/null; then
      # Find the castai-kvisor Chart.yaml (could be top-level or nested subchart)
      local chart_yaml
      chart_yaml=$(find "$tmpdir" -path "*/castai-kvisor/Chart.yaml" -print -quit 2>/dev/null)
      if [[ -n "$chart_yaml" ]]; then
        python3 -c "
import sys, yaml
data = yaml.safe_load(open('$chart_yaml'))
print(data.get('appVersion', ''))
" 2>/dev/null
      fi
    fi
    rm -rf "$tmpdir"
  }

  # Show kvisor version info — both what's deployed and what's available.
  # For umbrella charts, kvisor is locked to the umbrella version and can only be
  # updated by upgrading the umbrella chart (--upgrade-chart).
  if [[ -z "$SKIP_REPO" ]]; then
    if [[ -n "$VALUES_PREFIX" ]]; then
      # Umbrella chart: extract kvisor version from chart packages
      PINNED_KVISOR=""
      LATEST_UMBRELLA=""
      LATEST_KVISOR=""

      LATEST_UMBRELLA=$(helm search repo castai-helm/castai --output json 2>/dev/null \
        | python3 -c "
import sys, json
for e in json.load(sys.stdin):
    if e['name'] == 'castai-helm/castai':
        print(e['version'])
        break
" 2>/dev/null) || LATEST_UMBRELLA=""

      # Get kvisor version in the pinned umbrella chart
      if [[ -n "$CHART_VERSION" ]]; then
        PINNED_KVISOR=$(kvisor_version_in_chart "$CHART" --version "$CHART_VERSION")
      fi
      # Get kvisor version in the latest umbrella chart
      if [[ -n "$LATEST_UMBRELLA" && "$LATEST_UMBRELLA" != "$CHART_VERSION" ]]; then
        LATEST_KVISOR=$(kvisor_version_in_chart "$CHART" --version "$LATEST_UMBRELLA")
      elif [[ -n "$LATEST_UMBRELLA" ]]; then
        LATEST_KVISOR="$PINNED_KVISOR"
      fi

      # Display: "Deployed kvisor: v1.55.22 (chart 0.33.63 bundles v1.55.22, latest: 0.33.65 → v1.55.25)"
      if [[ -n "$DEPLOYED_KVISOR_VERSION" ]]; then
        info "Deployed kvisor: $DEPLOYED_KVISOR_VERSION"
      fi
      if [[ -n "$PINNED_KVISOR" ]]; then
        info "Pinned umbrella chart $CHART_VERSION includes kvisor $PINNED_KVISOR"
      fi
      if [[ -n "$LATEST_UMBRELLA" && "$LATEST_UMBRELLA" != "${CHART_VERSION:-}" ]]; then
        LATEST_MSG="Latest umbrella chart: $LATEST_UMBRELLA"
        if [[ -n "$LATEST_KVISOR" ]]; then
          LATEST_MSG="$LATEST_MSG (kvisor $LATEST_KVISOR)"
        fi
        info "$LATEST_MSG — use --upgrade-chart to update"
      elif [[ -n "$PINNED_KVISOR" && "$PINNED_KVISOR" == "$LATEST_KVISOR" ]]; then
        ok "Umbrella chart is up to date ($CHART_VERSION)"
      fi
    else
      # Standalone: compare kvisor versions directly
      LATEST_KVISOR_APP=$(helm search repo castai-helm/castai-kvisor --output json 2>/dev/null \
        | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['app_version'])" 2>/dev/null) || LATEST_KVISOR_APP=""

      if [[ -n "$DEPLOYED_KVISOR_VERSION" && -n "$LATEST_KVISOR_APP" ]]; then
        if [[ "$DEPLOYED_KVISOR_VERSION" == "$LATEST_KVISOR_APP" ]]; then
          ok "Kvisor $DEPLOYED_KVISOR_VERSION (up to date)"
        else
          info "Deployed kvisor: $DEPLOYED_KVISOR_VERSION → latest: $LATEST_KVISOR_APP (use --upgrade-chart to update)"
        fi
      elif [[ -n "$DEPLOYED_KVISOR_VERSION" ]]; then
        info "Deployed kvisor: $DEPLOYED_KVISOR_VERSION"
      fi
    fi
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

  # Show current reliability-related values in upgrade mode
  if [[ -n "$VERBOSE" ]]; then
    debug "Current reliability-related values in release '$RELEASE':"
    CURRENT_VALS=$(helm $HELM_CTX get values "$RELEASE" -n "$NAMESPACE" -o json 2>/dev/null | python3 -c "
import sys, json

def find_reliability(obj, path=''):
    if not isinstance(obj, dict):
        return
    for key, val in obj.items():
        current = f'{path}.{key}' if path else key
        if 'reliabilityMetrics' in key or 'reliability' in key:
            print(f'  {current} = {json.dumps(val, default=str)[:200]}')
        elif isinstance(val, dict):
            find_reliability(val, current)

find_reliability(json.load(sys.stdin))
" 2>/dev/null) || CURRENT_VALS=""
    if [[ -n "$CURRENT_VALS" ]]; then
      while IFS= read -r line; do debug "$line"; done <<< "$CURRENT_VALS"
    else
      debug "  (no reliability-related values found in current release)"
    fi
  fi
else
  warn "Release '$RELEASE' not found in namespace '$NAMESPACE'"
  debug "Install mode: FRESH INSTALL (no existing release)"

  # Auto-detect pre-existing credentials in the namespace.
  # These may exist from a previous installation, or be managed externally.
  debug "Scanning namespace '$NAMESPACE' for pre-existing credentials..."
  if [[ -z "$API_KEY" && -z "$API_KEY_SECRET" ]]; then
    for candidate in castai-kvisor castai-credentials; do
      if kubectl $KUBECTL_CTX get secret "$candidate" -n "$NAMESPACE" \
         -o jsonpath='{.data.API_KEY}' >/dev/null 2>&1; then
        API_KEY_SECRET="$candidate"
        ok "Auto-detected API key secret: $candidate"
        break
      fi
    done
  fi
  if [[ -z "$CLUSTER_ID" && -z "$CLUSTER_ID_SECRET" && -z "$CLUSTER_ID_CONFIGMAP" ]]; then
    # Check ConfigMap first (most common: castai-agent-metadata)
    if kubectl $KUBECTL_CTX get configmap castai-agent-metadata -n "$NAMESPACE" \
       -o jsonpath='{.data.CLUSTER_ID}' >/dev/null 2>&1; then
      CLUSTER_ID_CONFIGMAP="castai-agent-metadata"
      ok "Auto-detected cluster ID configmap: castai-agent-metadata"
    else
      # Fall back to Secret-based cluster ID
      for candidate in castai-kvisor castai-credentials; do
        if kubectl $KUBECTL_CTX get secret "$candidate" -n "$NAMESPACE" \
           -o jsonpath='{.data.CLUSTER_ID}' >/dev/null 2>&1; then
          CLUSTER_ID_SECRET="$candidate"
          ok "Auto-detected cluster ID secret: $candidate"
          break
        fi
      done
    fi
  fi

  # For fresh install, we need credentials from one of:
  #   1. --values-file (contains castai.apiKey/apiKeySecretRef + clusterID)
  #   2. --api-key + --cluster-id (inline)
  #   3. --api-key-secret + --cluster-id-secret (pre-existing Secrets)
  #   4. Auto-detected Secrets/ConfigMaps already on the cluster
  debug "Credential sources: API_KEY=${API_KEY:+(inline)} API_KEY_SECRET=${API_KEY_SECRET:-(none)} CLUSTER_ID=${CLUSTER_ID:+(inline)} CLUSTER_ID_SECRET=${CLUSTER_ID_SECRET:-(none)} CLUSTER_ID_CONFIGMAP=${CLUSTER_ID_CONFIGMAP:-(none)} VALUES_FILE=${VALUES_FILE:-(none)}"
  HAS_CREDS=""
  [[ -n "$VALUES_FILE" ]] && HAS_CREDS="true"
  [[ -n "$API_KEY" || -n "$API_KEY_SECRET" ]] && [[ -n "$CLUSTER_ID" || -n "$CLUSTER_ID_SECRET" || -n "$CLUSTER_ID_CONFIGMAP" ]] && HAS_CREDS="true"
  if [[ -z "$HAS_CREDS" ]]; then
    err "Fresh install requires credentials. Provide one of:"
    err "  --values-file <file>                     (values file with castai.* config)"
    err "  --api-key <key> --cluster-id <id>         (inline credentials)"
    err "  --api-key-secret <name> --cluster-id-secret <name>  (pre-existing Secrets)"
    err ""
    err "Or ensure these resources exist in namespace '$NAMESPACE':"
    err "  Secret 'castai-kvisor' or 'castai-credentials' with .data.API_KEY"
    err "  ConfigMap 'castai-agent-metadata' with .data.CLUSTER_ID"
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

# ── Verbose: Configuration Summary ──────────────────────────────────────────
if [[ -n "$VERBOSE" ]]; then
  step "Configuration Summary"
  debug "Mode:             ${INSTALL_MODE:+FRESH INSTALL}${INSTALL_MODE:-UPGRADE}"
  debug "Release:          $RELEASE"
  debug "Chart:            $CHART"
  debug "Namespace:        $NAMESPACE"
  debug "Chart version:    ${CHART_VERSION:-(latest)}${HELM_VERSION_FLAG:+ → $HELM_VERSION_FLAG}"
  debug "Values prefix:    ${VALUES_PREFIX:-(none, standalone)}"
  debug "Values file:      ${VALUES_FILE:-(none)}"
  debug "OBI profile:      $OBI_PROFILE"
  debug "Dynamic sizing:   $DYNAMIC_SIZING"
  debug "Storage class:    ${STORAGE_CLASS:-(cluster default)}"
  debug "Cluster proxy:    ${CLUSTER_PROXY:-false}"
  if [[ -n "$INSTALL_MODE" ]]; then
    if [[ -n "$API_KEY" ]]; then
      debug "API key source:   inline (--api-key)"
    elif [[ -n "$API_KEY_SECRET" ]]; then
      debug "API key source:   Secret '$API_KEY_SECRET'"
    else
      debug "API key source:   values file"
    fi
    if [[ -n "$CLUSTER_ID" ]]; then
      debug "Cluster ID src:   inline (--cluster-id)"
    elif [[ -n "$CLUSTER_ID_CONFIGMAP" ]]; then
      debug "Cluster ID src:   ConfigMap '$CLUSTER_ID_CONFIGMAP'"
    elif [[ -n "$CLUSTER_ID_SECRET" ]]; then
      debug "Cluster ID src:   Secret '$CLUSTER_ID_SECRET'"
    else
      debug "Cluster ID src:   values file"
    fi
  else
    debug "API key secret:   ${DETECTED_API_KEY_SECRET:-(chart default)}"
  fi
fi

# ── Phase 1: CRD Detection & Operator Bootstrap ─────────────────────────────
step "Phase 1: ClickHouse Operator CRD Check"

CRD_EXISTS=""
OPERATOR_RUNNING=""
if kubectl $KUBECTL_CTX get crd clickhouseinstallations.clickhouse.altinity.com >/dev/null 2>&1; then
  CRD_EXISTS="true"
  detect_operator || true
  if [[ -n "$OPERATOR_RUNNING" ]]; then
    ok "ClickHouseInstallation CRD exists and operator is running (in namespace: $OPERATOR_NS) — skipping operator install"
  elif [[ -n "$OPERATOR_WATCH_WARNING" ]]; then
    warn "ClickHouse operator found in namespace '$OPERATOR_NS' but it does NOT watch namespace '$NAMESPACE'"
    warn "The operator's WATCH_NAMESPACES does not include '$NAMESPACE' — ClickHouseInstallation CRs will be ignored"
    warn "Either add '$NAMESPACE' to the operator's WATCH_NAMESPACES or install a dedicated operator"
  else
    warn "ClickHouseInstallation CRD exists but operator is not running — will install operator"
  fi
fi

if [[ -n "$OPERATOR_RUNNING" ]]; then
  : # nothing to do
elif [[ -n "$CRD_EXISTS" ]]; then
  # CRD present but operator missing — run Phase 1 to reinstall the operator
  info "Reinstalling ClickHouse operator (CRD already registered, skipping CRD wait)..."

  PHASE1_CMD="$(build_helm_base)"

  if [[ -n "$INSTALL_MODE" ]]; then
    PHASE1_CMD="$PHASE1_CMD $(build_creds_flags)"
  else
    PHASE1_CMD="$PHASE1_CMD \\
  --reset-then-reuse-values"
    if [[ -n "$VALUES_FILE" ]]; then
      PHASE1_CMD="$PHASE1_CMD -f '${VALUES_FILE//"'"/"'\\''"}'"
    fi
  fi

  # Under the umbrella chart, the kvisor subchart is gated by a condition
  # (e.g. condition: castai-kvisor.enabled in autoscaler/Chart.yaml).
  # We must explicitly enable it so the subchart renders at all.
  if [[ -n "$VALUES_PREFIX" ]]; then
    PHASE1_CMD="$PHASE1_CMD \\
  $(setkey enabled=true)"
  fi
  PHASE1_CMD="$PHASE1_CMD \\
  $(setkey reliabilityMetrics.enabled=true) \\
  $(setkey reliabilityMetrics.operator.enabled=true) \\
  $(setkey reliabilityMetrics.install.enabled=false) \\
  $(setkey reliabilityMetrics.exporter.enabled=false)"

  run_cmd "$PHASE1_CMD"

  if [[ -z "$DRY_RUN" ]]; then
    info "Waiting for operator pod to be ready..."
    if ! kubectl $KUBECTL_CTX rollout status deployment -n "$NAMESPACE" -l app=clickhouse-operator --timeout=60s 2>/dev/null; then
      warn "Operator rollout did not complete within 60s"
      if [[ -n "$VERBOSE" ]]; then
        debug "Operator pods:"
        kubectl $KUBECTL_CTX get pods -n "$NAMESPACE" -l app=clickhouse-operator -o wide 2>/dev/null \
          | while IFS= read -r line; do debug "  $line"; done
      fi
    else
      ok "ClickHouse operator ready"
    fi
  fi
else
  warn "ClickHouseInstallation CRD not found"
  info "Installing ClickHouse operator first (Phase 1)..."
  info "This deploys ONLY the operator + CRD, without enabling the full stack."

  # Phase 1: Install just the operator to register the CRD.
  # We explicitly disable install.enabled so the ClickHouseInstallation CR isn't created yet.
  PHASE1_CMD="$(build_helm_base)"

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

  # Under the umbrella chart, the kvisor subchart is gated by a condition
  # (e.g. condition: castai-kvisor.enabled in autoscaler/Chart.yaml).
  # We must explicitly enable it so the subchart renders at all.
  if [[ -n "$VALUES_PREFIX" ]]; then
    PHASE1_CMD="$PHASE1_CMD \\
  $(setkey enabled=true)"
  fi
  PHASE1_CMD="$PHASE1_CMD \\
  $(setkey reliabilityMetrics.enabled=true) \\
  $(setkey reliabilityMetrics.operator.enabled=true) \\
  $(setkey reliabilityMetrics.install.enabled=false) \\
  $(setkey reliabilityMetrics.exporter.enabled=false)"

  run_cmd "$PHASE1_CMD"

  if [[ -z "$DRY_RUN" ]]; then
    # Check if the operator deployment was actually created
    if [[ -n "$VERBOSE" ]]; then
      echo ""
      debug "Checking for operator deployment after Phase 1 helm upgrade..."
      OPERATOR_DEPLOY=$(kubectl $KUBECTL_CTX get deployments -n "$NAMESPACE" \
        -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.readyReplicas}/{.status.replicas}{"\n"}{end}' 2>/dev/null \
        | grep -i "clickhouse" || true)
      if [[ -n "$OPERATOR_DEPLOY" ]]; then
        debug "Operator deployment(s) found:"
        while IFS= read -r line; do debug "  $line"; done <<< "$OPERATOR_DEPLOY"
      else
        debug "No deployment with 'clickhouse' in name found in namespace '$NAMESPACE'"
        debug "All deployments in namespace:"
        kubectl $KUBECTL_CTX get deployments -n "$NAMESPACE" -o custom-columns=NAME:.metadata.name,READY:.status.readyReplicas,REPLICAS:.status.replicas 2>/dev/null \
          | while IFS= read -r line; do debug "  $line"; done
      fi

      debug "Pods in namespace (clickhouse-related):"
      kubectl $KUBECTL_CTX get pods -n "$NAMESPACE" 2>/dev/null | grep -iE "clickhouse|operator" \
        | while IFS= read -r line; do debug "  $line"; done
      if ! kubectl $KUBECTL_CTX get pods -n "$NAMESPACE" 2>/dev/null | grep -iq "clickhouse"; then
        debug "No clickhouse/operator pods found at all"
      fi
    fi

    info "Waiting for CRD to be registered..."
    TRIES=0
    MAX_TRIES=30
    while ! kubectl $KUBECTL_CTX get crd clickhouseinstallations.clickhouse.altinity.com >/dev/null 2>&1; do
      TRIES=$((TRIES + 1))
      if [[ $TRIES -ge $MAX_TRIES ]]; then
        err "Timed out waiting for ClickHouseInstallation CRD (${MAX_TRIES}s)"
        err "Check operator logs: kubectl logs -n $NAMESPACE -l app=clickhouse-operator"

        # Verbose: dump diagnostics on timeout
        if [[ -n "$VERBOSE" ]]; then
          echo ""
          debug "=== Timeout Diagnostics ==="
          debug "Operator pods:"
          kubectl $KUBECTL_CTX get pods -n "$NAMESPACE" -l app=clickhouse-operator -o wide 2>/dev/null \
            | while IFS= read -r line; do debug "  $line"; done
          if ! kubectl $KUBECTL_CTX get pods -n "$NAMESPACE" -l app=clickhouse-operator 2>/dev/null | grep -q "clickhouse"; then
            debug "  (none found with label app=clickhouse-operator)"
            debug "All pods in namespace:"
            kubectl $KUBECTL_CTX get pods -n "$NAMESPACE" -o wide 2>/dev/null \
              | while IFS= read -r line; do debug "  $line"; done
          fi

          debug "Operator deployment details:"
          kubectl $KUBECTL_CTX get deployments -n "$NAMESPACE" -o wide 2>/dev/null \
            | grep -iE "clickhouse|NAME" | while IFS= read -r line; do debug "  $line"; done

          debug "Recent events (operator/CRD related):"
          kubectl $KUBECTL_CTX get events -n "$NAMESPACE" --sort-by='.lastTimestamp' 2>/dev/null \
            | grep -iE "clickhouse|operator|crd" | tail -10 \
            | while IFS= read -r line; do debug "  $line"; done

          debug "Operator container logs (last 20 lines):"
          kubectl $KUBECTL_CTX logs -n "$NAMESPACE" -l app=clickhouse-operator --tail=20 2>/dev/null \
            | while IFS= read -r line; do debug "  $line"; done
          if [[ $? -ne 0 ]]; then
            debug "  (no logs available — pod may not exist)"
          fi

          debug "Helm release manifest check — does the operator template exist?"
          OPERATOR_IN_MANIFEST=$(helm $HELM_CTX get manifest "$RELEASE" -n "$NAMESPACE" 2>/dev/null \
            | grep -c "clickhouse-operator" || echo "0")
          debug "  'clickhouse-operator' appears $OPERATOR_IN_MANIFEST times in rendered manifest"

          debug "CRDs currently registered:"
          kubectl $KUBECTL_CTX get crd 2>/dev/null | grep -i "clickhouse" \
            | while IFS= read -r line; do debug "  $line"; done
          if ! kubectl $KUBECTL_CTX get crd 2>/dev/null | grep -iq "clickhouse"; then
            debug "  (no clickhouse CRDs found)"
          fi
          debug "=== End Diagnostics ==="
        fi

        exit 1
      fi
      printf "."
      sleep 1
    done
    echo ""
    ok "ClickHouseInstallation CRD is now available"
    CRD_EXISTS="true"
  fi
fi

fi # end of [[ -z "$PRINT_ONLY" ]] — cluster-dependent sections

# ── StorageClass check (print-only mode) ─────────────────────────────────────
# When running in print-only mode, the preflight block above is skipped.
# Still check for a default StorageClass since it's a kubectl-only read.
if [[ -n "$PRINT_ONLY" ]]; then
  if [[ -n "$STORAGE_CLASS" ]]; then
    ok "StorageClass override: $STORAGE_CLASS (via --storage-class)"
  else
    DEFAULT_SC=$(kubectl $KUBECTL_CTX get sc -o jsonpath='{range .items[?(@.metadata.annotations.storageclass\.kubernetes\.io/is-default-class=="true")]}{.metadata.name}{"\n"}{end}' 2>/dev/null) || DEFAULT_SC=""
    if [[ -z "$DEFAULT_SC" ]]; then
      warn "No default StorageClass found! ClickHouse PVC will stay Pending."
      info "Fix: re-run with --storage-class <name>, or mark a default:"
      if kubectl $KUBECTL_CTX get sc gp2 >/dev/null 2>&1; then
        info "  kubectl annotate storageclass gp2 storageclass.kubernetes.io/is-default-class=true"
      elif kubectl $KUBECTL_CTX get sc gp3 >/dev/null 2>&1; then
        info "  kubectl annotate storageclass gp3 storageclass.kubernetes.io/is-default-class=true"
      fi
      echo ""
    else
      ok "Default StorageClass: $DEFAULT_SC"
    fi
  fi
fi

# ── Auto-detect OBI profile ──────────────────────────────────────────────────
# Runs outside the print-only guard — only needs kubectl (not helm).
# Falls back gracefully if the cluster isn't reachable.
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

# ── CRD / Operator Detection ─────────────────────────────────────────────────
# Read-only kubectl checks — runs in all modes (including print-only) so we
# know whether Phase 1 is needed. Falls back gracefully if cluster unreachable.
if [[ -z "$CRD_EXISTS" ]]; then
  # Only check if not already set by the cluster-dependent block above
  if kubectl $KUBECTL_CTX get crd clickhouseinstallations.clickhouse.altinity.com >/dev/null 2>&1; then
    CRD_EXISTS="true"
    detect_operator || true
  fi
fi

# Rebuild version flag (may have been set inside the cluster-dependent block, or via --chart-version)
HELM_VERSION_FLAG=""
if [[ -n "$CHART_VERSION" ]]; then
  HELM_VERSION_FLAG="--version $CHART_VERSION"
fi

# ── Print-only: Phase 1 (operator bootstrap) ────────────────────────────────
# Show Phase 1 only when the operator isn't already running and watching our namespace.
if [[ -n "$PRINT_ONLY" && -z "$OPERATOR_RUNNING" ]]; then
  if [[ -n "$OPERATOR_WATCH_WARNING" ]]; then
    step "Phase 1: ClickHouse Operator — WARNING"
    warn "ClickHouse operator found in namespace '$OPERATOR_NS' but does NOT watch '$NAMESPACE'"
    warn "Either add '$NAMESPACE' to the operator's WATCH_NAMESPACES env var,"
    warn "or run Command #1 below to install a dedicated operator in '$NAMESPACE'."
    echo ""
  elif [[ -n "$CRD_EXISTS" ]]; then
    step "Phase 1: Install ClickHouse Operator"
    warn "CRD exists but operator is not running — Phase 1 will reinstall it"
    echo ""
  else
    step "Phase 1: Install ClickHouse Operator"
    info "ClickHouse CRD not found — Phase 1 installs the operator and registers the CRD"
    echo ""
  fi

  PHASE1_CMD="$(build_helm_base)"

  if [[ -n "$INSTALL_MODE" ]]; then
    PHASE1_CMD="$PHASE1_CMD $(build_creds_flags)"
  else
    PHASE1_CMD="$PHASE1_CMD \\
  --reset-then-reuse-values"
    if [[ -n "$VALUES_FILE" ]]; then
      PHASE1_CMD="$PHASE1_CMD -f '${VALUES_FILE//"'"/"'\\''"}'"
    fi
  fi

  # Under the umbrella chart, the kvisor subchart is gated by a condition
  # (e.g. condition: castai-kvisor.enabled in autoscaler/Chart.yaml).
  # We must explicitly enable it so the subchart renders at all.
  if [[ -n "$VALUES_PREFIX" ]]; then
    PHASE1_CMD="$PHASE1_CMD \\
  $(setkey enabled=true)"
  fi
  PHASE1_CMD="$PHASE1_CMD \\
  $(setkey reliabilityMetrics.enabled=true) \\
  $(setkey reliabilityMetrics.operator.enabled=true) \\
  $(setkey reliabilityMetrics.install.enabled=false) \\
  $(setkey reliabilityMetrics.exporter.enabled=false)"

  print_cmd_block "Command #1 — Install operator" "$PHASE1_CMD"
  echo ""
  info "Then wait for CRD before running command #2:"
  print_cmd_block "Wait for CRD" "kubectl wait --for=condition=Established \\
  crd/clickhouseinstallations.clickhouse.altinity.com --timeout=60s"
  echo ""
elif [[ -n "$PRINT_ONLY" ]]; then
  ok "ClickHouse operator already running (namespace: ${OPERATOR_NS:-$NAMESPACE}) — skipping Phase 1"
fi

# ── Phase 2: Enable Full Reliability Stack ───────────────────────────────────
step "Phase 2: Enabling Full Reliability Stack"

# Build the helm command with all reliability flags
HELM_CMD="$(build_helm_base)"

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

# Under the umbrella chart, ensure the kvisor subchart itself is enabled
if [[ -n "$VALUES_PREFIX" ]]; then
  HELM_CMD="$HELM_CMD \\
  $(setkey enabled=true)"
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

# Enable cluster proxy if requested
if [[ -n "$CLUSTER_PROXY" ]]; then
  HELM_CMD="$HELM_CMD \\
  $(setkey controller.extraArgs.cluster-proxy-enabled=true)"
  info "Cluster proxy enabled"
fi

# Override ClickHouse StorageClass if specified
if [[ -n "$STORAGE_CLASS" ]]; then
  HELM_CMD="$HELM_CMD \\
  $(setkey reliabilityMetrics.install.persistence.storageClass=$STORAGE_CLASS)"
  info "ClickHouse StorageClass: $STORAGE_CLASS"
fi

info "OBI sizing profile: $OBI_PROFILE"
info "Dynamic sizing: $DYNAMIC_SIZING"

if [[ -n "$PRINT_ONLY" ]]; then
  print_cmd_block "Command #2 — Enable full reliability stack" "$HELM_CMD"
else
  echo ""
  run_cmd "$HELM_CMD"
fi

# ── Print-only: Common Overrides ─────────────────────────────────────────────
if [[ -n "$PRINT_ONLY" ]]; then
  echo ""
  step "Common Overrides (add to Phase 2 command above)"
  echo ""
  echo "  # OBI: which ports to instrument (controls process discovery)"
  echo "  $(setkey 'agent.reliabilityMetrics.obi.openPorts=8080\,8443\,6379\,5432')"
  echo ""
  echo "  # OBI: sizing profile (small/medium/large/xlarge) — or use --obi-profile flag"
  echo "  $(setkey agent.reliabilityMetrics.obi.sizingProfile=large)"
  echo ""
  echo "  # OBI: enable dynamic sizing (auto-checks process count at startup)"
  echo "  $(setkey agent.reliabilityMetrics.obi.dynamicSizing=true)"
  echo ""
  echo "  # OBI: exclude a namespace from instrumentation (use -f values file for multiple)"
  echo "  $(setkey 'agent.reliabilityMetrics.obi.exclude[0].k8s_namespace=monitoring')"
  echo ""
  echo "  # ClickHouse: increase memory for large clusters (100+ nodes)"
  echo "  $(setkey reliabilityMetrics.install.resources.limits.memory=4Gi)"
  echo ""
  echo "  # ClickHouse: increase disk for high-cardinality workloads"
  echo "  $(setkey reliabilityMetrics.install.persistence.size=200Gi)"
  echo ""
  echo "  # ClickHouse: explicit StorageClass (or use --storage-class flag)"
  echo "  $(setkey reliabilityMetrics.install.persistence.storageClass=gp3)"
  echo ""
  echo "  # ClickHouse: credentials from existing Secret"
  echo "  $(setkey 'reliabilityMetrics.auth.password.valueFrom.secretKeyRef.name=my-ch-secret')"
  echo "  $(setkey 'reliabilityMetrics.auth.password.valueFrom.secretKeyRef.key=password')"
  echo ""
  echo "  # Cluster proxy (or use --cluster-proxy flag)"
  echo "  $(setkey controller.extraArgs.cluster-proxy-enabled=true)"
  echo ""
  echo "  # Use a values file instead of --set flags (recommended for complex configs)"
  echo "  # Script flag: -f /path/to/values.yaml"
  echo ""
  echo "  # Full docs: docs/reliability-stack-installation.md"
  echo "  # OBI sizing: docs/obi-sizing.md"
fi

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
if [[ -z "$PRINT_ONLY" ]]; then
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
  if [[ -n "$STORAGE_CLASS" ]]; then
    echo "  StorageClass:   $STORAGE_CLASS"
  fi
  echo ""
  echo "Next steps:"
  echo "  • Verify ClickHouse is ready:  kubectl get chi -n $NAMESPACE"
  echo "  • Check OBI logs:              kubectl logs -n $NAMESPACE <agent-pod> -c obi"
  echo "  • Run OBI sizing report:       ./charts/kvisor/scripts/obi-sizing-report.sh"
  echo "  • View sizing guide:           docs/obi-sizing.md"
  echo ""
fi
