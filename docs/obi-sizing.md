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

> **Recommended limit** = Peak + 30 MiB headroom, clamped to [120, 1024] MiB.
> The `obi-init` dynamic sizing check uses a simplified formula (`40 + N × 27 + 30`)
> for warning thresholds — this is intentionally less conservative than the table above.

## Configuring `openPorts`

The `openPorts` setting controls **process discovery** — OBI finds processes listening
on these ports and instruments them. Once discovered, **all** HTTP/gRPC traffic from
that process is instrumented across all ports (not just the configured ones). The number
of discovered processes directly affects memory usage.

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

## GOMEMLIMIT: Cgroup-Aware Runtime Derivation

OBI's `GOMEMLIMIT` is **always** derived at runtime from the container's actual cgroup
memory limit — not from a static Helm value. An init container (`obi-init`) generates
an entrypoint script that:

1. Reads the container's enforced memory limit from the cgroup filesystem
   - cgroup v2: `/sys/fs/cgroup/<path>/memory.max` (where path comes from `/proc/self/cgroup`)
   - cgroup v1 fallback: `/sys/fs/cgroup/memory/<path>/memory.limit_in_bytes`
2. Sets `GOMEMLIMIT` to **90% of the actual limit**
3. Launches OBI with the calculated value

This ensures `GOMEMLIMIT` automatically tracks VPA (Vertical Pod Autoscaler) mutations,
admission webhook overrides, and any other post-Helm changes to the container's memory
limit — avoiding a class of OOMKill caused by a stale static `GOMEMLIMIT` exceeding
the container's actual budget.

## Dynamic Sizing (Optional)

For heterogeneous clusters where node density varies significantly, enable
dynamic sizing. This extends the init container to also scan the node's processes
and log a per-node memory recommendation.

```yaml
agent:
  reliabilityMetrics:
    enabled: true
    obi:
      sizingProfile: "xlarge"        # Set ceiling for busiest node
      dynamicSizing: true            # Scan processes + warn if limit too low
      openPorts: "8080,8443,8090,6379"
```

### How It Works

1. The `obi-init` init container runs before OBI starts
2. It enumerates **all network namespaces** on the node by scanning `/proc/[0-9]*/ns/net`
   and deduplicating by inode (since `hostPID: true` gives visibility into all pods)
3. For each unique netns, it reads `/proc/<pid>/net/tcp` and `/proc/<pid>/net/tcp6`
   to find processes listening on configured `openPorts`
4. Calculates recommended memory: `40 + (N × 27) + 30` MiB, clamped to [120, 1024]
5. Writes the recommendation to `/shared/obi-recommended-mem`
6. At startup, the entrypoint script compares the recommendation against the
   cgroup-derived limit and **warns** if the limit is too low
7. `GOMEMLIMIT` is always set from the cgroup limit (not the recommendation)

### When to Use Dynamic Sizing

| Scenario | Recommendation |
|----------|----------------|
| Homogeneous nodes (all similar workload density) | Static profile is sufficient |
| Heterogeneous nodes (mix of quiet and busy) | **Use dynamic sizing** |
| Frequent workload rebalancing / scaling events | **Use dynamic sizing** |
| Strict security requirements (no SYS_PTRACE) | Static profile only |
| Unknown workload density | Run the helper script first, then decide |

### Limitations

- **Startup only**: Calculates at pod creation time. If workloads arrive after OBI
  starts, the value becomes stale (pod restarts recalculate).
- **GOMEMLIMIT only**: Adjusts Go's GC pressure but does not change Kubernetes
  `limits.memory`. Set limits high enough for the busiest expected node.
- **Adds ~2-5s to pod startup**: The init container runs quickly but adds sequential
  startup time.
- **Requires SYS_PTRACE on init container**: The `obi-init` init container needs
  this capability to traverse network namespaces of other processes. Note: the OBI
  container itself always has SYS_PTRACE regardless of this setting.

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
> ./charts/kvisor/scripts/obi-sizing-report.sh -p 8080,8443 | head -40
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

### Init Container Logs

The `obi-init` container always runs when reliability metrics are enabled (it sets up
the cgroup-aware entrypoint). When `dynamicSizing` is also enabled, it additionally
logs the process scan results:

```bash
kubectl logs <pod> -c obi-init

# Always present (cgroup-aware GOMEMLIMIT):
# Output: "obi-init: cgroup memory limit = 805306368 bytes"
# Output: "obi-init: setting GOMEMLIMIT to 90% = 691MiB"

# With dynamicSizing enabled:
# Output: "obi-init: scanning network namespaces for listening processes..."
# Output: "obi-init: found 15 unique netns, 23 processes on ports 8080,8443,8090,6379"
# Output: "obi-init: recommended memory = 691 MiB"
```

### Reducing Instrumented Process Count

If OBI uses too much memory, reduce the number of instrumented processes:

1. **Narrow `openPorts`**: Remove ports that don't serve user traffic (e.g., 6379 for Redis)
2. **Exclude namespaces/services**: Use `obi.exclude` to skip entire namespaces or specific binaries
3. **Exclude profilers**: Enable `obi.excludeProfilerEndpoints` (default: true) to prevent
   profiler agents from being instrumented and producing misleading 10s P95 latencies
4. **Ignore routes**: Use `obi.ignoredRoutes` to drop `/debug/pprof/*`, `/healthz`, etc.

See [Service Exclusions](#service-exclusions) below.

## Service Exclusions

OBI supports three mechanisms to reduce noise and memory usage by excluding
processes or URL paths from instrumentation.

### Process Exclusions (`exclude`)

Skip entire processes from being instrumented. Each entry can match on:
`exe_path`, `k8s_namespace`, `open_ports`, `container_name`, `k8s_pod_labels`,
`k8s_pod_annotations`, `cmd_args` (glob patterns supported).

```yaml
agent:
  reliabilityMetrics:
    obi:
      exclude:
        - k8s_namespace: "monitoring"
        - k8s_namespace: "loki"
        - exe_path: "*prometheus*"
        - open_ports: "9090,9091"
```

See: [OBI Service Discovery — Exclude Services](https://opentelemetry.io/docs/zero-code/obi/configure/service-discovery/#exclude-services-from-instrumentation)

### Profiler Endpoint Exclusion (`excludeProfilerEndpoints`)

Enabled by default (`true`). This is a convenience toggle that:

1. **Excludes profiler agent processes** from instrumentation: parca, pyroscope,
   grafana-agent, alloy — preventing their outbound scrape calls from appearing
   as instrumented traffic
2. **Drops `/debug/pprof/*` and `/debug/*` URL paths** — these are Go pprof
   endpoints that block for 10-30s during CPU profiling, producing misleading
   10,000ms P95 latency spikes in RED metrics

```yaml
agent:
  reliabilityMetrics:
    obi:
      excludeProfilerEndpoints: true   # default
```

### Route Exclusions (`ignoredRoutes`)

Drop specific URL paths from metrics and traces. Uses glob patterns with `*` wildcard.
Matched requests are silently dropped by OBI before export.

The chart ships with sensible defaults covering health probes, Prometheus endpoints,
Spring Boot actuator, debug/pprof, and Jolokia. Override only if you need to customize:

```yaml
agent:
  reliabilityMetrics:
    obi:
      # Default ignored routes (override to customize):
      ignoredRoutes:
        # Health / readiness probes
        - /health
        - /health/*
        - /healthz
        - /readyz
        - /livez
        - /ready
        - /up
        - /ping
        # Prometheus / metrics endpoints
        - /metrics
        - /metrics/*
        # Spring Boot actuator
        - /actuator/*
        # Profiling / debug
        - /debug/*
        - /debug/pprof/*
        # JVM management (Jolokia)
        - /jolokia
        - /jolokia/*
```

To add custom routes while keeping defaults, include all defaults plus your additions.
Setting `ignoredRoutes` replaces the entire list — it does not merge with defaults.

See: [OBI Routes Decorator](https://opentelemetry.io/docs/zero-code/obi/configure/routes-decorator/)

### How It Works (ConfigMap)

Exclusion and route settings are YAML-only OBI features with no env var equivalent.
When any exclusions are configured, the Helm chart creates a ConfigMap
(`<release>-kvisor-agent-obi-config`) mounted at `/etc/obi/obi-config.yaml`, and
sets `OTEL_EBPF_CONFIG_PATH` to point OBI at it. Other OBI settings (ports, OTLP
endpoint, etc.) continue using env vars, which take precedence over YAML config.
