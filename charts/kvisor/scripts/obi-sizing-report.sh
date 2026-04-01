#!/usr/bin/env bash
# obi-sizing-report.sh — Analyze a Kubernetes cluster to determine optimal OBI memory sizing.
#
# This script uses only 'kubectl get' commands to count containers listening on
# the configured ports across all nodes, then applies the OBI memory formula and
# outputs per-nodepool sizing recommendations.
#
# No special permissions needed — only 'kubectl get pods' and 'kubectl get nodes'.
#
# Usage:
#   ./obi-sizing-report.sh [--ports PORTS] [--context CONTEXT] [--nodepool-label LABEL]
#
# Requirements:
#   - kubectl with read access to the cluster
#   - python3 (for JSON parsing; available on all modern systems)

set -euo pipefail

# ──────────────────────────────────────────────────────────────
# Constants: OBI memory formula (empirically validated on v0.6.0)
# ──────────────────────────────────────────────────────────────
readonly OBI_BASE_MIB=40       # Base overhead (Go runtime, maps, core structs)
readonly OBI_PER_PROC_MIB=27   # Per instrumented process (symbols, ring buffer, aggregation)
readonly OBI_HEADROOM_MIB=30   # ELF parsing spike buffer
readonly OBI_MIN_MIB=120       # Minimum viable (covers base + 1 process + headroom)
readonly OBI_MAX_MIB=1024      # Maximum recommendation

# ──────────────────────────────────────────────────────────────
# Defaults
# ──────────────────────────────────────────────────────────────
PORTS="8080,8443,8090,6379"
KUBE_CONTEXT=""
NODEPOOL_LABEL=""
MACHINE_OUTPUT=""

# ──────────────────────────────────────────────────────────────
# Usage
# ──────────────────────────────────────────────────────────────
usage() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Analyze cluster nodes to determine optimal OBI memory sizing.

Uses 'kubectl get pods' to count containers exposing the target ports on each
node, then applies the OBI memory formula to produce sizing recommendations.
No special cluster permissions required — only read access.

Options:
  --ports PORTS           Comma-separated ports to check (default: $PORTS)
  --context CONTEXT       kubectl context to use (default: current context)
  --nodepool-label LABEL  Node label for grouping by nodepool
                          (default: auto-detect from cloud provider labels)
  --machine               Machine-readable output (single line, key=value pairs)
                          Used by enable-reliability-stack.sh --obi-profile auto
  -h, --help              Show this help

Examples:
  $(basename "$0")
  $(basename "$0") --ports 8080,8443
  $(basename "$0") --context prod-cluster --ports 8080,8443,8090,6379
  $(basename "$0") --nodepool-label "cloud.google.com/gke-nodepool"
  $(basename "$0") --machine  # outputs: PROFILE=medium DYNAMIC=false MAX_PROCS=12

Memory Formula:
  Steady-state = $OBI_BASE_MIB + (N × $OBI_PER_PROC_MIB) MiB
  Peak         = Steady-state + 50 MiB (ELF parsing)
  Recommended  = Steady-state + $OBI_HEADROOM_MIB MiB  (clamped to [$OBI_MIN_MIB, $OBI_MAX_MIB])
EOF
  exit 0
}

# ──────────────────────────────────────────────────────────────
# Parse arguments
# ──────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --ports)      PORTS="$2"; shift 2 ;;
    --context)    KUBE_CONTEXT="$2"; shift 2 ;;
    --nodepool-label) NODEPOOL_LABEL="$2"; shift 2 ;;
    --machine)    MACHINE_OUTPUT="true"; shift ;;
    -h|--help)    usage ;;
    *)            echo "Unknown option: $1" >&2; usage ;;
  esac
done

# ──────────────────────────────────────────────────────────────
# Kubectl wrapper
# ──────────────────────────────────────────────────────────────
KUBECTL="kubectl"
if [[ -n "$KUBE_CONTEXT" ]]; then
  KUBECTL="kubectl --context=$KUBE_CONTEXT"
fi

# ──────────────────────────────────────────────────────────────
# Auto-detect nodepool label
# ──────────────────────────────────────────────────────────────
detect_nodepool_label() {
  local labels
  labels=$($KUBECTL get nodes -o jsonpath='{.items[0].metadata.labels}' 2>/dev/null) || true

  if echo "$labels" | grep -q "cloud.google.com/gke-nodepool"; then
    echo "cloud.google.com/gke-nodepool"
  elif echo "$labels" | grep -q "eks.amazonaws.com/nodegroup"; then
    echo "eks.amazonaws.com/nodegroup"
  elif echo "$labels" | grep -q "agentpool"; then
    echo "agentpool"
  elif echo "$labels" | grep -q "node.kubernetes.io/instance-type"; then
    echo "node.kubernetes.io/instance-type"
  else
    echo "node.kubernetes.io/instance-type"
  fi
}

# ──────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────
main() {
  if [[ -z "$MACHINE_OUTPUT" ]]; then
    echo ""
    echo "OBI Sizing Report"
    echo "═══════════════════════════════════════════════════════════════════"
    echo ""
  fi

  # Check deps
  if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 is required but not found in PATH." >&2
    exit 1
  fi

  local cluster_name
  cluster_name=$($KUBECTL config current-context 2>/dev/null || echo "unknown")
  [[ -n "$KUBE_CONTEXT" ]] && cluster_name="$KUBE_CONTEXT"

  if [[ -z "$MACHINE_OUTPUT" ]]; then
    echo "Cluster:          $cluster_name"
    echo "Ports analyzed:   $PORTS"
    echo "Date:             $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo ""
  fi

  # Detect nodepool label
  if [[ -z "$NODEPOOL_LABEL" ]]; then
    NODEPOOL_LABEL=$(detect_nodepool_label)
  fi
  if [[ -z "$MACHINE_OUTPUT" ]]; then
    echo "Nodepool label:   $NODEPOOL_LABEL"
    echo ""
  fi

  # Fetch pods & nodes in a single pass each
  local tmpdir
  tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/obi-sizing.XXXXXX")
  trap "rm -rf '$tmpdir'" EXIT INT TERM

  [[ -z "$MACHINE_OUTPUT" ]] && echo "Fetching node metadata..." >&2
  $KUBECTL get nodes -o json > "$tmpdir/nodes.json" 2>/dev/null
  [[ -z "$MACHINE_OUTPUT" ]] && echo "Fetching pod data (all namespaces)..." >&2
  $KUBECTL get pods -A --field-selector=status.phase=Running -o json > "$tmpdir/pods.json" 2>/dev/null

  [[ -z "$MACHINE_OUTPUT" ]] && echo "" >&2

  # Python does all the heavy lifting: match ports, aggregate per node/pool, format report
  python3 - "$PORTS" "$NODEPOOL_LABEL" "$OBI_BASE_MIB" "$OBI_PER_PROC_MIB" "$OBI_HEADROOM_MIB" "$OBI_MIN_MIB" "$OBI_MAX_MIB" "$tmpdir/nodes.json" "$tmpdir/pods.json" "${MACHINE_OUTPUT:-}" <<'PYEOF'
import sys, json

# ── Parse args ───────────────────────────────────────────────
args = sys.argv[1:]
ports_str, nodepool_label, base, per_proc, headroom, min_mib, max_mib, nodes_file, pods_file = args[:9]
machine_output = args[9] if len(args) > 9 else ""
target_ports = set(int(p) for p in ports_str.split(","))
BASE = int(base)
PER_PROC = int(per_proc)
HEADROOM = int(headroom)
MIN_MIB = int(min_mib)
MAX_MIB = int(max_mib)

# ── Read JSON files ──────────────────────────────────────────
with open(nodes_file) as f:
    nodes_data = json.load(f)
with open(pods_file) as f:
    pods_data = json.load(f)

# ── Build node → pool mapping ────────────────────────────────
# Handle dotted label keys (e.g. "node.kubernetes.io/instance-type")
node_pool = {}
for node in nodes_data.get("items", []):
    name = node["metadata"]["name"]
    labels = node["metadata"].get("labels", {})
    pool = labels.get(nodepool_label, "unknown")
    node_pool[name] = pool

# ── Count containers per node matching target ports ──────────
node_procs = {}  # node_name → count of matching containers
for pod in pods_data.get("items", []):
    node = pod["spec"].get("nodeName", "")
    if not node:
        continue
    if node not in node_procs:
        node_procs[node] = 0
    for container in pod["spec"].get("containers", []):
        container_ports = set()
        for p in container.get("ports", []):
            cp = p.get("containerPort")
            if cp is not None:
                container_ports.add(int(cp))
        if container_ports & target_ports:
            node_procs[node] += 1

# Include nodes with 0 matching containers
for name in node_pool:
    if name not in node_procs:
        node_procs[name] = 0

# ── Sizing functions ─────────────────────────────────────────
def calc_steady(n):  return BASE + n * PER_PROC
def calc_peak(n):    return calc_steady(n) + 50
def calc_rec(n):     return max(MIN_MIB, min(MAX_MIB, calc_steady(n) + HEADROOM))
def profile(n):
    if n <= 5:  return "Small"
    if n <= 15: return "Medium"
    if n <= 30: return "Large"
    return "X-Large"

def limit_bucket(mem):
    if mem <= 256:  return "256Mi", "96Mi"
    if mem <= 384:  return "384Mi", "128Mi"
    if mem <= 512:  return "512Mi", "192Mi"
    if mem <= 768:  return "768Mi", "384Mi"
    return "1Gi", "512Mi"

# ── Per-node report ──────────────────────────────────────────
total_nodes = len(node_procs)
nodes_with_procs = sum(1 for n in node_procs.values() if n > 0)

if machine_output != "true":
    print(f"Nodes scanned:    {total_nodes}")
    print(f"Nodes with match: {nodes_with_procs} ({nodes_with_procs*100//max(total_nodes,1)}%)")
    print()

fmt = "{:<45s} {:<22s} {:>6s} {:>9s} {:>9s} {:>12s} {:>8s}"
pfmt = "{:<22s} {:>6s} {:>6s} {:>6s} {:>6s} {:>18s} {:>8s}"

if machine_output != "true":
    print("Per-Node Analysis (nodes with matching containers)")
    print("─" * 80)
    print(fmt.format("NODE", "POOL", "PROCS", "STEADY", "PEAK", "RECOMMEND", "PROFILE"))
    print()

# Sort by pool, then descending procs
rows = []
for node, procs in sorted(node_procs.items(), key=lambda x: (node_pool.get(x[0], ""), -x[1])):
    if procs == 0:
        continue
    pool = node_pool.get(node, "unknown")
    st = calc_steady(procs)
    pk = calc_peak(procs)
    rec = calc_rec(procs)
    prof = profile(procs)
    rows.append((node, pool, procs, st, pk, rec, prof))
    if machine_output != "true":
        print(fmt.format(node, pool, str(procs), f"{st} Mi", f"{pk} Mi", f"{rec} Mi", prof))

if machine_output != "true":
    print()

# ── Per-pool summary ─────────────────────────────────────────
pool_stats = {}  # pool → {nodes, min, max, sum, max_mem}
for node, procs in node_procs.items():
    pool = node_pool.get(node, "unknown")
    if pool not in pool_stats:
        pool_stats[pool] = {"nodes": 0, "min": 999999, "max": 0, "sum": 0, "max_mem": 0}
    s = pool_stats[pool]
    s["nodes"] += 1
    s["sum"] += procs
    if procs < s["min"]: s["min"] = procs
    if procs > s["max"]: s["max"] = procs
    rec = calc_rec(procs)
    if rec > s["max_mem"]: s["max_mem"] = rec

if machine_output != "true":
    print("Per-Nodepool Summary")
    print("─" * 80)
    print(pfmt.format("POOL", "NODES", "MIN", "MAX", "AVG", "RECOMMENDED LIMIT", "PROFILE"))
    print()

overall_max_procs = 0
overall_max_mem = 0
global_min = 999999
global_max = 0

for pool in sorted(pool_stats):
    s = pool_stats[pool]
    avg = s["sum"] // max(s["nodes"], 1)
    limit_str, _ = limit_bucket(s["max_mem"])
    prof = profile(s["max"])
    if machine_output != "true":
        print(pfmt.format(pool, str(s["nodes"]), str(s["min"]), str(s["max"]), str(avg), limit_str, prof))

    if s["max"] > overall_max_procs: overall_max_procs = s["max"]
    if s["max_mem"] > overall_max_mem: overall_max_mem = s["max_mem"]
    if s["min"] < global_min: global_min = s["min"]
    if s["max"] > global_max: global_max = s["max"]

if machine_output != "true":
    print()

# Clamp sentinel values for empty clusters
if global_min == 999999:
    global_min = 0

# ── Suggested values.yaml ────────────────────────────────────
rec_profile = profile(overall_max_procs).lower().replace("-", "")

# Determine if dynamic sizing should be recommended
# High variance = ratio of max to min+1 >= 3
high_variance = global_max > 0 and global_max // (global_min + 1) >= 3
rec_dynamic = "true" if high_variance else "false"

# ── Machine-readable output (for scripting) ──────────────────
if machine_output == "true":
    print(f"PROFILE={rec_profile} DYNAMIC={rec_dynamic} MAX_PROCS={overall_max_procs} MIN_PROCS={global_min} NODES={total_nodes}")
    sys.exit(0)

print("Suggested values.yaml")
print("─" * 80)
print()
print(f"  # Recommended sizing profile based on max observed density")
print(f"  # ({overall_max_procs} containers on busiest node):")
print(f"  agent:")
print(f"    reliabilityMetrics:")
print(f"      enabled: true")
print(f"      obi:")
print(f'        sizingProfile: "{rec_profile}"')
print(f'        openPorts: "{ports_str}"')
print()

# Show what the profile maps to
profile_map = {
    "small":  ("96Mi",  "256Mi"),
    "medium": ("192Mi", "512Mi"),
    "large":  ("384Mi", "768Mi"),
    "xlarge": ("512Mi", "1Gi"),
}
req, lim = profile_map.get(rec_profile, ("192Mi", "512Mi"))
print(f"  # Profile '{rec_profile}' → requests: {req}, limits: {lim}")
print()

# Check variance for dynamic sizing recommendation
if high_variance:
    print(f"  # ⚡ High variance detected ({global_min}–{global_max} containers/node).")
    print(f"  # Consider dynamic sizing to auto-tune per node:")
    print(f"  agent:")
    print(f"    reliabilityMetrics:")
    print(f"      enabled: true")
    print(f"      obi:")
    print(f'        sizingProfile: "xlarge"        # Set ceiling for busiest node')
    print(f"        dynamicSizing: true            # Auto-calculate GOMEMLIMIT per node")
    print(f'        openPorts: "{ports_str}"')
    print()

# Custom sizing option
print(f"  # Or use custom sizing for full control:")
print(f"  agent:")
print(f"    reliabilityMetrics:")
print(f"      enabled: true")
print(f"      obi:")
print(f'        sizingProfile: "custom"')
print(f'        openPorts: "{ports_str}"')
print(f"        resources:")
print(f"          requests:")
print(f"            memory: {req}")
print(f"          limits:")
print(f"            memory: {lim}")
print()

print()
print(f"Total: {total_nodes} nodes, {nodes_with_procs} with matching containers, max {overall_max_procs} on one node")
print()
print(f"Formula: steady = {BASE} + (N × {PER_PROC}) MiB")
print(f"         recommended = steady + {HEADROOM} MiB  (clamped to [{MIN_MIB}, {MAX_MIB}])")
print()
print("Available profiles:")
print("  small  — up to 5 services/node   (requests: 96Mi,  limits: 256Mi)")
print("  medium — 5–15 services/node      (requests: 192Mi, limits: 512Mi)")
print("  large  — 15–30 services/node     (requests: 384Mi, limits: 768Mi)")
print("  xlarge — 30+ services/node       (requests: 512Mi, limits: 1Gi)")
print("  custom — manual resources block")
print()
print("NOTE: Counts are based on declared containerPorts in pod specs.")
print("      Processes listening on unlisted ports won't be detected.")
print("      Use dynamicSizing for exact runtime counts.")
print()
print("See docs/obi-sizing.md for detailed configuration guidance.")
print()
PYEOF
}

main "$@"
