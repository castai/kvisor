# OBI Sizing Guide

> **Part of the Reliability Metrics stack** — see [Reliability Stack Installation Guide](reliability-stack-installation.md) for full setup instructions.

OBI (OpenTelemetry eBPF Instrumentation) runs as a sidecar container in the kvisor
agent DaemonSet. It uses eBPF to collect RED metrics (request rate, error rate, duration
histograms) from application workloads without requiring code changes or sidecars in
customer pods.

## Why Memory Usage Varies Per Node

OBI instruments **processes that listen on configured ports**. Each instrumented process
consumes memory for:

- ELF symbol table parsing (one-time spike at discovery)
- Per-process eBPF ring buffers
- Span/metric aggregation state
- Go runtime overhead

Because Kubernetes schedules different workloads on different nodes, the number of
instrumented processes varies significantly across nodes. A node running 3 microservices
uses ~120 MiB, while a node running 30 uses ~850 MiB.

## Memory Formula

```
Steady-state = 40 MiB (base) + N × 27 MiB (per instrumented process)
Peak         = Steady-state + 50 MiB (ELF parsing spike at startup)
```

Where **N** = number of processes listening on configured `openPorts` on the node.

### Example Calculations

| Processes on node | Steady-state | Peak (startup) | Recommended limit |
|-------------------|-------------|----------------|-------------------|
| 1                 | 67 MiB      | 117 MiB        | 150 MiB           |
| 3                 | 121 MiB     | 171 MiB        | 220 MiB           |
| 5                 | 175 MiB     | 225 MiB        | 290 MiB           |
| 10                | 310 MiB     | 360 MiB        | 460 MiB           |
| 15                | 445 MiB     | 495 MiB        | 640 MiB           |
| 20                | 580 MiB     | 630 MiB        | 820 MiB           |
| 30                | 850 MiB     | 900 MiB        | 1024 MiB          |

> **Recommended limit** includes 30 MiB headroom above peak, clamped to [120, 1024] MiB.

## Configuring `openPorts`

The `openPorts` setting controls **which ports OBI instruments**. Only processes
listening on these ports are tracked. This directly affects memory usage.

```yaml
agent:
  reliabilityMetrics:
    enabled: true
    obi:
      openPorts: "8080,8443,8090,6379"
```

### Choosing Ports

| Port | Typical Use | Include? |
|------|-------------|----------|
| `8080` | HTTP APIs (Spring Boot, Express, Flask, Go net/http) | ✅ Yes — primary HTTP traffic |
| `8443` | HTTPS APIs | ✅ Yes — TLS-terminated services |
| `8090` | gRPC APIs | ✅ Yes — gRPC services |
| `6379` | Redis | ⚠️ Optional — useful for DB latency tracking |
| `3306` | MySQL | ⚠️ Optional — database latency |
| `5432` | PostgreSQL | ⚠️ Optional — database latency |
| `9090` | Prometheus metrics endpoints | ❌ No — high cardinality, not user traffic |
| `9200` | Elasticsearch | ⚠️ Optional — adds ~27 MiB per ES pod |

**Rule of thumb**: Include ports that serve customer-facing traffic. Exclude
infrastructure/monitoring ports (Prometheus, health checks) to reduce memory overhead.

### Impact of Port Selection on Memory

Each additional port doesn't cost memory by itself — what costs memory is the **number
of processes** that happen to listen on those ports. For example:

- `openPorts: "8080"` on a node with 10 services on port 8080 → 10 processes → ~310 MiB
- `openPorts: "8080,8443,8090,6379"` on the same node, if only 10 services match → same 310 MiB
- `openPorts: "8080,8443,8090,6379"` with 3 Redis pods also on the node → 13 processes → ~391 MiB

## Sizing Profiles

OBI supports named sizing profiles that map to predefined memory requests/limits.
Set `sizingProfile` in your `values.yaml` — no need to calculate resources manually.

```
┌────────────────────────────────┬─────────────────┬──────────────────┐
│ Profile                        │ Memory Request   │ Memory Limit     │
├────────────────────────────────┼─────────────────┼──────────────────┤
│ small  (< 5 services/node)    │ 96Mi            │ 256Mi            │
│ medium (5–15 services/node)   │ 192Mi           │ 512Mi (default)  │
│ large  (15–30 services/node)  │ 384Mi           │ 768Mi            │
│ xlarge (30+ services/node)    │ 512Mi           │ 1Gi              │
│ custom                         │ (user-defined)  │ (user-defined)   │
└────────────────────────────────┴─────────────────┴──────────────────┘
```

Where "services/node" = count of containers listening on configured `openPorts` per node.

### Applying a Profile

```yaml
# Use a named profile (recommended):
agent:
  reliabilityMetrics:
    enabled: true
    obi:
      sizingProfile: "large"
      openPorts: "8080,8443,8090,6379"
```

### Custom Sizing

For full control over resource values, use the `custom` profile with an explicit
`resources` block:

```yaml
agent:
  reliabilityMetrics:
    enabled: true
    obi:
      sizingProfile: "custom"
      openPorts: "8080,8443,8090,6379"
      resources:
        requests:
          memory: 400Mi
        limits:
          memory: 800Mi
```

## Detecting Optimal Sizing

Use the included helper script to analyze your cluster and get per-nodepool
recommendations. The script uses only `kubectl get pods` and `kubectl get nodes` —
no special permissions, no exec, no debug containers.

**Requirements**: `kubectl` with read access to the cluster, `python3`.

```bash
# Basic usage (uses default ports: 8080,8443,8090,6379)
./charts/kvisor/scripts/obi-sizing-report.sh

# Custom ports
./charts/kvisor/scripts/obi-sizing-report.sh --ports 8080,8443

# Specific context
./charts/kvisor/scripts/obi-sizing-report.sh --context prod-cluster --ports 8080,8443
```

The script:
1. Fetches all running pods and their declared `containerPort` values
2. Matches container ports against the target `openPorts`
3. Counts matching containers per node (≈ processes OBI will instrument)
4. Applies the memory formula
5. Groups results by nodepool (auto-detected from cloud provider labels)
6. Outputs recommended `values.yaml` settings

> **Note**: Counts are based on declared `containerPort` in pod specs. Processes
> listening on undeclared ports won't be detected. For exact runtime counts,
> enable `dynamicSizing` which probes `/proc/net/tcp` at pod startup.

### Example Output

```
OBI Sizing Report
═════════════════════════════════════════════════════════════════

Cluster:          prod-cluster
Ports analyzed:   8080,8443

Nodes scanned:    188
Nodes with match: 80 (42%)

Per-Node Analysis (nodes with matching containers)
────────────────────────────────────────────────────────────────
NODE                                          POOL                  PROCS  STEADY      PEAK     RECOMMEND  PROFILE
gke-prod-cast-pool-521d416f                   c2d-highmem-32           22   634 Mi    684 Mi      664 Mi    Large
gke-prod-cast-pool-656bc8c9                   c2d-standard-56          19   553 Mi    603 Mi      583 Mi    Large
gke-prod-cast-pool-dc246266                   c2d-standard-32          17   499 Mi    549 Mi      529 Mi    Large
gke-prod-cast-pool-650882f0                   c2d-standard-112         12   364 Mi    414 Mi      394 Mi   Medium
gke-prod-cast-pool-48cb64eb                   n2d-highcpu-16            9   283 Mi    333 Mi      313 Mi   Medium
...

Per-Nodepool Summary
────────────────────────────────────────────────────────────────
POOL                 NODES  MIN  MAX  AVG  RECOMMENDED LIMIT  PROFILE
c2d-highmem-32          15    1   22    6          768Mi       Large
c2d-standard-32          1   17   17   17          768Mi       Large
c2d-standard-56          3    7   19   11          768Mi       Large
c2d-standard-112         2   12   12   12          512Mi      Medium
n2d-highcpu-16           2    9    9    9          384Mi      Medium
c2d-highmem-8           29    0    3    0          256Mi       Small
n2d-highcpu-8           26    0    0    0          256Mi       Small
...

Suggested values.yaml
────────────────────────────────────────────────────────────────
  # Recommended sizing profile based on max observed density
  # (22 containers on busiest node):
  agent:
    reliabilityMetrics:
      enabled: true
      obi:
        sizingProfile: "large"
        openPorts: "8080,8443"

  # Profile 'large' → requests: 384Mi, limits: 768Mi

  # ⚡ High variance detected (0–22 containers/node).
  # Consider dynamic sizing to auto-tune per node:
  agent:
    reliabilityMetrics:
      enabled: true
      obi:
        sizingProfile: "xlarge"
        dynamicSizing: true
        openPorts: "8080,8443"

  # Or use custom sizing for full control:
  agent:
    reliabilityMetrics:
      enabled: true
      obi:
        sizingProfile: "custom"
        openPorts: "8080,8443"
        resources:
          requests:
            memory: 384Mi
          limits:
            memory: 768Mi
```

## Dynamic Sizing (Automatic)

For heterogeneous clusters where node density varies significantly, enable
dynamic sizing. This adds a lightweight init container that counts processes
at pod startup and sets `GOMEMLIMIT` accordingly.

```yaml
agent:
  reliabilityMetrics:
    enabled: true
    obi:
      sizingProfile: "xlarge"        # Set ceiling for busiest node
      dynamicSizing: true            # Auto-calculate GOMEMLIMIT per node
      openPorts: "8080,8443,8090,6379"
```

### How It Works

1. An init container (`obi-sizer`) runs before OBI starts
2. It counts processes listening on `openPorts` via `/proc/net/tcp` (host namespace)
3. Calculates: `40 + (N × 27) + 30` MiB, clamped to [120, 1024] MiB
4. Writes the value to a shared volume
5. OBI starts with `GOMEMLIMIT` set to the calculated value
6. Go's garbage collector tunes itself to the actual per-node requirements

### When to Use Dynamic Sizing

| Scenario | Recommendation |
|----------|----------------|
| Homogeneous nodes (all similar workload density) | Static profile is sufficient |
| Heterogeneous nodes (mix of quiet and busy) | **Use dynamic sizing** |
| Frequent workload rebalancing / scaling events | **Use dynamic sizing** |
| Strict security requirements (no extra init containers) | Static profile |
| Unknown workload density | Run the helper script first, then decide |

### Limitations

- **Startup only**: Calculates at pod creation time. If workloads arrive after OBI
  starts, the value becomes stale (pod restarts recalculate).
- **GOMEMLIMIT only**: Adjusts Go's GC pressure but does not change Kubernetes
  `limits.memory`. Set limits high enough for the busiest expected node.
- **Adds ~2-5s to pod startup**: The init container runs quickly but adds sequential
  startup time.

## Achieving Uniform Node Density

OBI runs as a DaemonSet sidecar — every node gets the same resource limits. When pod
density is uneven (e.g., 3 processes on one node, 25 on another), you're forced to
size for the worst case, wasting memory on quiet nodes. Leveling out pod distribution
lets you use a **smaller profile** and avoids OOMKills on hot nodes.

### Why It Matters

```
Before (skewed):    Node A: 25 pods → xlarge needed    Node B: 3 pods → small would suffice
After  (balanced):  Node A: 14 pods → medium           Node B: 14 pods → medium
```

A `medium` profile uses 512Mi limit vs `xlarge` at 1Gi — **50% memory savings on every node**.

### 1. Topology Spread Constraints (Recommended)

The most direct way to even out distribution. Add this to your Deployments to spread
pods across nodes:

```yaml
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      topologySpreadConstraints:
        - maxSkew: 1                        # Max difference in pod count between nodes
          topologyKey: kubernetes.io/hostname
          whenUnsatisfiable: ScheduleAnyway # Soft constraint — don't block scheduling
          labelSelector:
            matchLabels:
              app: my-service
```

| Field | Recommendation |
|-------|---------------|
| `maxSkew` | `1` for strict balance, `2–3` for flexibility with autoscaling |
| `whenUnsatisfiable` | `ScheduleAnyway` (soft) for production, `DoNotSchedule` (hard) for strict control |
| `topologyKey` | `kubernetes.io/hostname` for per-node spread |

> **Tip:** Apply topology constraints to your **top 3–5 highest-replica Deployments** first.
> These typically drive the density variance. Use the sizing report to identify which
> workloads cause spikes:
> ```bash
> ./scripts/obi-sizing-report.sh -p 8080,8443 | head -40
> ```

### 2. Pod Anti-Affinity

Prevents multiple replicas of the same service from stacking on one node. Best for
stateful services or databases:

```yaml
spec:
  template:
    spec:
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
            - weight: 100
              podAffinityTerm:
                labelSelector:
                  matchLabels:
                    app: my-service
                topologyKey: kubernetes.io/hostname
```

Use `preferredDuringScheduling` (soft) rather than `requiredDuringScheduling` (hard) to
avoid blocking pod scheduling when nodes are scarce.

### 3. Descheduler (Continuous Rebalancing)

Kubernetes only makes placement decisions at scheduling time. If nodes become skewed
after scale-ups, autoscaler events, or rolling updates, the
[Descheduler](https://github.com/kubernetes-sigs/descheduler) can rebalance:

```yaml
# Descheduler policy — evict pods from overloaded nodes
apiVersion: descheduler/v1alpha2
kind: DeschedulerPolicy
profiles:
  - name: rebalance
    pluginConfig:
      - name: LowNodeUtilization
        args:
          thresholds:
            pods: 30          # Node is "underutilized" below 30% pod capacity
          targetThresholds:
            pods: 50          # Node is "overutilized" above 50% pod capacity
      - name: RemoveDuplicates  # Spreads duplicate pods across nodes
    plugins:
      balance:
        enabled:
          - LowNodeUtilization
          - RemoveDuplicates
```

> **Caution:** Descheduler evicts pods, causing brief restarts. Ensure your services
> have proper PodDisruptionBudgets (PDBs) configured.

### 4. Node Pool Isolation

Separate high-density workloads (API gateways, data pipelines) from low-density ones
(batch jobs, cron) using dedicated node pools with taints:

```yaml
# High-density node pool (tolerates many OBI-instrumented services)
apiVersion: v1
kind: Node
metadata:
  labels:
    workload-type: api-services
spec:
  taints:
    - key: workload-type
      value: api-services
      effect: NoSchedule
```

Then on Deployments:

```yaml
spec:
  template:
    spec:
      nodeSelector:
        workload-type: api-services
      tolerations:
        - key: workload-type
          value: api-services
```

This lets you assign different OBI profiles per node pool via Helm overrides:

```bash
# DaemonSet doesn't natively support per-node-pool overrides, but you can
# use dynamic sizing to auto-tune GOMEMLIMIT per node:
agent:
  reliabilityMetrics:
    enabled: true
    obi:
      sizingProfile: "xlarge"        # Set ceiling for busiest pool
      dynamicSizing: true            # Auto-tune down on quiet pools
```

### 5. Quick Checklist

| Action | Impact on OBI Sizing | Effort |
|--------|---------------------|--------|
| Add `topologySpreadConstraints` to top Deployments | ⬇️ Reduces max density, smaller profile | Low |
| Enable `RemoveDuplicates` in Descheduler | ⬇️ Prevents hot-spot buildup over time | Medium |
| Separate node pools by workload type | ⬇️ Predictable per-pool density | Medium |
| Enable `dynamicSizing: true` | ⬇️ Auto-tunes GC per node (complementary) | Low |
| Review `openPorts` — remove unnecessary ports | ⬇️ Fewer tracked processes = less memory | Low |

## Troubleshooting

### OBI OOMKilled

```bash
# Check which node the pod was on
kubectl get pod <pod> -o wide

# Count containers with matching ports on that node
kubectl get pods -A --field-selector=spec.nodeName=<node>,status.phase=Running \
  -o jsonpath='{range .items[*]}{range .spec.containers[*]}{range .ports[*]}{.containerPort}{"\n"}{end}{end}{end}' \
  | grep -cE '^(8080|8443|8090|6379)$'
```

If the process count × 27 + 90 exceeds your memory limit, increase the limit or
enable dynamic sizing.

### Checking Current GOMEMLIMIT

```bash
# On a running OBI container
kubectl exec <pod> -c obi -- cat /proc/1/environ | tr '\0' '\n' | grep GOMEMLIMIT
```

### Init Container Logs (when dynamic sizing is enabled)

```bash
kubectl logs <pod> -c obi-sizer
# Output: "obi-sizer: discovered N listening processes on ports [8080,8443,8090,6379]"
# Output: "obi-sizer: setting GOMEMLIMIT=XXXMiB"
```
