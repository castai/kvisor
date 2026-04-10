# Kvisor Reliability Metrics Installation Guide

> **BETA**
>
> This feature is in beta. Core functionality is stable and running in production, but APIs and configurations may still evolve.

This guide covers installing Kvisor with the reliability metrics stack, which provides automated observability for applications running in your Kubernetes cluster.

## Overview

The reliability metrics stack extends Kvisor with eBPF-based application instrumentation (OBI) and automatic golden signal metrics collection (latency, error rate, throughput) for HTTP, gRPC, database, and messaging protocols.

### Architecture

```
Per-node (DaemonSet)                       Per-cluster (Deployment)
┌─────────────────────────────────────┐    ┌─────────────────────────┐
│  kvisor-agent pod                   │    │  kvisor-controller pod  │
│  ┌─────┐  ┌─────┐  ┌────────────┐  │    │  ┌──────────┐  ┌─────┐ │
│  │kvisor│  │ OBI │─▶│OTel        │  │    │  │controller│  │OTel │ │
│  │      │  │(eBPF)│  │Collector  │──┼──┐ │  │          │  │(k8s │ │
│  └─────┘  └─────┘  └────────────┘  │  │ │  └──────────┘  │recv)│ │
└─────────────────────────────────────┘  │ │                └──┬──┘ │
                                         │ └───────────────────┼────┘
                     ┌───────────────────┘                     │
                     ▼                                         ▼
          ┌─────────────────────────────────────────────────────┐
          │  ClickHouse pod (Altinity operator)                 │
          │  ┌───────────┐  ┌──────────────┐                   │
          │  │ClickHouse │  │ ch-exporter  │──▶ CAST AI gRPC   │
          │  │  (metrics) │  │ (sidecar)    │                    │
          │  └───────────┘  └──────────────┘                   │
          └─────────────────────────────────────────────────────┘
```

**Components:**

| Component | Location | Purpose |
|-----------|----------|---------|
| **OBI** (eBPF instrumenter) | Agent DaemonSet sidecar | Auto-instruments HTTP/gRPC/DB/messaging processes via eBPF, emits OTLP metrics |
| **OTel Collector** (agent) | Agent DaemonSet sidecar | Filters golden signals, converts cumulative-to-delta, writes to ClickHouse |
| **OTel Collector** (controller) | Controller Deployment sidecar | Collects K8s state metrics (pod health, deployments, HPA) via k8s_cluster receiver |
| **ClickHouse** | StatefulSet (via Altinity operator) | Stores Bronze (raw OTel) and Silver (1-minute aggregated) tables |
| **ch-exporter** | ClickHouse pod sidecar | Polls Silver tables, exports to CAST AI via gRPC |
| **Migrate job** | Helm hook (post-install/upgrade) | Runs goose migrations to create/update the ClickHouse schema |

### Data Flow

```
OBI (eBPF probes) ──OTLP──▶ OTel Collector ──SQL INSERT──▶ ClickHouse
                              │                              │
                              │ Pipelines:                   │ Tables:
                              │  1. Prometheus (cumulative)   │  Bronze: otel_metrics_histogram/gauge
                              │  2. ClickHouse (delta)        │  Silver: reliability_metrics_{http,grpc,db,messaging,gauge}
                              │                               │
                              ▼                               ▼
                        Prometheus scrape              ch-exporter ──gRPC──▶ CAST AI
```

## Prerequisites

- Kubernetes cluster (1.25+)
- **Linux kernel ≥ 5.8** on all nodes (required for eBPF ring buffers and BTF support)
- **Architecture**: amd64 or arm64 (OBI compiles eBPF programs for both; no 32-bit support)
- `helm` (3.12+) and `kubectl` installed and configured
- CAST AI account with API key and cluster onboarded to CAST AI
- **Altinity ClickHouse operator**: Either let the chart install it (`reliabilityMetrics.operator.enabled=true`) or ensure one is already running in the cluster (`reliabilityMetrics.operator.enabled=false`)

> **Preflight check**: The `enable-reliability-stack.sh` script automatically checks kernel version and architecture on all nodes before proceeding. If any node fails, you'll be prompted to confirm before continuing.

### Helm Repo Setup

```bash
helm repo add castai-helm https://castai.github.io/helm-charts
helm repo update castai-helm
```

## Installation

### Recommended: Automated Script

The `enable-reliability-stack.sh` script handles the ClickHouse Operator CRD bootstrapping automatically. It detects whether the CRD exists, installs the operator first if needed, waits for the CRD to register, then enables the full stack.

```bash
# Basic usage (existing kvisor installation, auto-detects OBI profile)
./charts/kvisor/scripts/enable-reliability-stack.sh

# With context and explicit profile
./charts/kvisor/scripts/enable-reliability-stack.sh \
  --context <kube-context> \
  --obi-profile large \
  --dynamic-sizing

# With a custom values file (overrides openPorts, exclusions, ClickHouse config, etc.)
./charts/kvisor/scripts/enable-reliability-stack.sh \
  --context <kube-context> \
  -f /path/to/my-values.yaml

# Dry-run (prints commands without executing)
./charts/kvisor/scripts/enable-reliability-stack.sh --dry-run
```

The `-f` / `--values-file` flag layers your values file on top of the chart defaults and any previously-set user values (via `--reset-then-reuse-values`). This is the recommended way to configure `openPorts`, exclusions, ClickHouse resources, and exporter settings for production clusters.

Run `./charts/kvisor/scripts/enable-reliability-stack.sh --help` for all options.

### Option 1: Fresh Installation

```bash
helm install castai-kvisor castai-helm/castai-kvisor \
  -n castai-agent --create-namespace \
  --set castai.apiKey=<your-api-key> \
  --set castai.clusterID=<your-cluster-id> \
  --set castai.grpcAddr=<grpc-endpoint> \
  --set agent.reliabilityMetrics.enabled=true \
  --set controller.reliabilityMetrics.enabled=true \
  --set reliabilityMetrics.enabled=true \
  --set reliabilityMetrics.operator.enabled=true \
  --set reliabilityMetrics.install.enabled=true \
  --set reliabilityMetrics.exporter.enabled=true
```

### Option 2: Enable on Existing Kvisor (Manual)

> **⚠️ CRD Chicken-and-Egg Problem**
>
> If the cluster has no ClickHouse Operator CRD (`clickhouse.altinity.com/v1`), enabling `reliabilityMetrics.install.enabled=true` will fail with:
> ```
> no matches for kind "ClickHouseInstallation" in version "clickhouse.altinity.com/v1"
> ```
> **Solution:** Use the automated script above, or perform a two-phase manual install:
> 1. First deploy just the operator (must use `helm install` or `helm upgrade --install`, not plain `helm upgrade`, so CRDs get installed):
>    `--set reliabilityMetrics.operator.enabled=true --set reliabilityMetrics.install.enabled=false`
> 2. Wait for CRD: `kubectl get crd clickhouseinstallations.clickhouse.altinity.com`
> 3. Then enable the full stack with `--set reliabilityMetrics.install.enabled=true`

```bash
helm repo update castai-helm

helm upgrade castai-kvisor castai-helm/castai-kvisor \
  -n castai-agent \
  --reset-then-reuse-values \
  --set agent.reliabilityMetrics.enabled=true \
  --set controller.reliabilityMetrics.enabled=true \
  --set reliabilityMetrics.enabled=true \
  --set reliabilityMetrics.operator.enabled=true \
  --set reliabilityMetrics.install.enabled=true \
  --set reliabilityMetrics.exporter.enabled=true
```

**Important:** Use `--reset-then-reuse-values` (not `--reuse-values`) when enabling reliability metrics. `--reuse-values` can cause template errors due to new nested configuration values. `--reset-then-reuse-values` starts from chart defaults and applies previous release values on top, safely merging new structures.

## Configuration

### Three Enable Flags

The stack requires three independent enable flags because the components live in different parts of the chart:

| Flag | What it enables |
|------|-----------------|
| `agent.reliabilityMetrics.enabled` | OBI sidecar + OTel Collector in the agent DaemonSet |
| `controller.reliabilityMetrics.enabled` | OTel Collector (k8s_cluster receiver) in the controller Deployment |
| `reliabilityMetrics.enabled` | Subchart: ClickHouse, migrations, ch-exporter |

### Minimal Values File

```yaml
castai:
  apiKey: <your-api-key>
  clusterID: <your-cluster-id>
  grpcAddr: <grpc-endpoint>

agent:
  reliabilityMetrics:
    enabled: true

controller:
  reliabilityMetrics:
    enabled: true

reliabilityMetrics:
  enabled: true
  install:
    enabled: true
  exporter:
    enabled: true
```

### Full Configuration Reference

```yaml
agent:
  reliabilityMetrics:
    enabled: true
    # OBI-specific settings
    obi:
      # Sizing profile (small, medium, large, xlarge, custom)
      sizingProfile: "medium"
      # Dynamic sizing — scans all network namespaces at startup to count
      # instrumented processes and warn if container limit is too low
      dynamicSizing: false
      # OBI image
      image:
        repository: otel/ebpf-instrument
        tag: "v0.7.1"
      # OBI resources (scales with instrumented processes, ~27 MiB each)
      # Used only when sizingProfile is "custom"; otherwise profile resources are applied
      resources:
        requests:
          memory: 128Mi
        limits:
          memory: 512Mi
      # Ports to instrument (comma-separated)
      openPorts: "8080,8443,8090,6379"
      # OBI tuning environment variables
      env:
        OTEL_TRACES_SAMPLER: "always_off"                    # Metrics only, no traces
        OTEL_EBPF_TRACE_PRINTER: "disabled"                  # Disable trace output
        OTEL_EBPF_CHANNEL_BUFFER_LEN: "50"                   # Internal channel buffer (default 10)
        OTEL_EBPF_METRICS_INTERVAL: "15s"                    # Flush interval (default: 60s)
        OTEL_EBPF_BPF_WAKEUP_LEN: "10"                      # Batch eBPF events per wakeup
        OTEL_EBPF_KUBE_META_RESTRICT_LOCAL_NODE: "true"      # Only cache local node metadata
        OTEL_EBPF_KUBE_DISABLE_INFORMERS: "node,service"    # Disable unused informers
        OTEL_EBPF_BPF_HTTP_REQUEST_TIMEOUT: "30s"            # Force-close long-lived HTTP connections
        OTEL_EBPF_BPF_HIGH_REQUEST_VOLUME: "true"            # Ring-buffer mode for high-throughput nodes
      # Service discovery exclusions — skip processes from instrumentation
      # Each entry can use: exe_path, k8s_namespace, open_ports, container_name, etc.
      exclude: []
        # - k8s_namespace: "monitoring"
        # - exe_path: "*prometheus*"
      # Exclude profiler agents (parca, pyroscope, alloy) and /debug/pprof/* routes
      # Prevents misleading 10s P95 latency from Go pprof scraping
      excludeProfilerEndpoints: true
      # URL paths to exclude from metrics (glob patterns).
      # Chart ships sensible defaults — override only if you need to customize.
      ignoredRoutes:
        # ── Health / readiness probes ──
        - /health
        - /health/*
        - /healthz
        - /readyz
        - /livez
        - /ready
        - /up
        - /ping
        # ── Prometheus / metrics endpoints ──
        - /metrics
        - /metrics/*
        # ── Spring Boot actuator ──
        - /actuator/*
        # ── Profiling / debug ──
        - /debug/*
        - /debug/pprof/*
        # ── JVM management (Jolokia) ──
        - /jolokia
        - /jolokia/*
      # Custom OBI container security context (overrides default eBPF capabilities)
      containerSecurityContext: {}
      # Internal metrics — exposes OBI's own health via Prometheus endpoint
      internalMetrics:
        enabled: false
        port: 6061                   # HTTP port for internal metrics
        path: "/internal/metrics"    # Scrape path
        podMonitor:
          enabled: false
          labels: {}
          interval: 30s
          scrapeTimeout: 10s
```

> **📖 See also:** [OBI Sizing Guide](obi-sizing.md) for sizing profiles, the sizing report script,
> dynamic sizing, and pod placement strategies to optimize OBI memory usage.

```yaml
    # OTel Collector sidecar (agent)
    collector:
      enabled: true
      image:
        repository: us-docker.pkg.dev/castai-hub/library/reliability-metrics-otel-collector
        tag: "v0.1.11"
      resources:
        requests:
          memory: 128Mi
        limits:
          memory: 256Mi
      prometheusPort: 9400
      clickhouseExporter:
        enabled: true
        address: "tcp://castai-kvisor-clickhouse.castai-agent.svc.cluster.local:9000"
      # PodMonitor for Prometheus Operator (scrapes collector self-metrics on port 8888)
      podMonitor:
        enabled: false
        labels: {}           # Extra labels for Prometheus Operator selector filtering
        interval: 30s
        scrapeTimeout: 10s

controller:
  reliabilityMetrics:
    enabled: true
    collector:
      enabled: true
      resources:
        requests:
          cpu: 250m
          memory: 256Mi
        limits:
          memory: 512Mi
      prometheusPort: 9401
      # PodMonitor for Prometheus Operator (scrapes collector self-metrics on port 8889)
      podMonitor:
        enabled: false
        labels: {}
        interval: 30s
        scrapeTimeout: 10s

# Subchart (reliability-metrics-ch-exporter)
reliabilityMetrics:
  enabled: true

  # CAST AI connectivity (for the ch-exporter)
  castai:
    apiKeySecretRef: "castai-kvisor"
    # Direct value (preferred for TF-managed clusters):
    clusterID: ""
    # OR from ConfigMap (default):
    clusterIdConfigMapRef:
      name: "castai-agent-metadata"
      key: "CLUSTER_ID"
    # Telemetry server gRPC address. The ch-exporter uses this to send
    # aggregated metrics to the CAST AI mothership. Unlike the kvisor agent
    # (which auto-derives telemetry.* from castai.grpcAddr), the exporter
    # needs an explicit address.
    # EU region: "telemetry.prod-eu.cast.ai:443"
    grpcAddr: "telemetry.prod-master.cast.ai:443"

  # ClickHouse credentials
  auth:
    database: "metrics"
    username: "kvisor"
    password: "kvisor"     # Override with valueFrom.secretKeyRef for production

  # Altinity ClickHouse operator
  operator:
    enabled: false         # Set true to install operator; false if already present

  # In-cluster ClickHouse deployment (via ClickHouseInstallation CR)
  install:
    enabled: true
    image:
      repository: clickhouse/clickhouse-server
      tag: "25.12.6-alpine"
    resources:
      requests:
        cpu: 500m
        memory: 1Gi
      limits:
        memory: 2Gi
    persistence:
      size: 100Gi

  # ch-exporter sidecar
  exporter:
    enabled: true
    grpcAddr: ""           # Defaults to reliabilityMetrics.castai.grpcAddr if empty
    image:
      repository: ghcr.io/castai/kvisor/reliability-metrics-ch-exporter
      tag: "v0.3.16"
    resources:
      requests:
        cpu: 50m
        memory: 64Mi
      limits:
        memory: 128Mi
    # PodMonitor for Prometheus Operator (scrapes exporter metrics on port 8080)
    podMonitor:
      enabled: false
      labels: {}
      selectorLabels: {}    # Override auto-detected pod selector
      interval: 30s
      scrapeTimeout: 10s

  # External ClickHouse (alternative to install.enabled)
  external:
    enabled: false
    address: ""            # host:port (native protocol)
    database: "metrics"
```

### Using an Existing Altinity Operator

If your cluster already has an Altinity ClickHouse operator (e.g., installed by another team):

```yaml
reliabilityMetrics:
  enabled: true
  operator:
    enabled: false     # Don't install a second operator
  install:
    enabled: true      # Deploy ClickHouse via existing operator
```

**Important:** If the existing operator has namespace-scoped watches, ensure it watches the `castai-agent` namespace, or the ClickHouseInstallation CR will be ignored.

### Using ClickHouse Credentials from Secrets

For production, avoid plaintext passwords in values. Use Terraform or a Secret manager:

```yaml
reliabilityMetrics:
  auth:
    database: "metrics"
    username: "kvisor"
    password:
      valueFrom:
        secretKeyRef:
          name: "my-clickhouse-secret"
          key: "password"
```

## Verification

### 1. Check Pod Status

```bash
kubectl get pods -n castai-agent -l app.kubernetes.io/instance=castai-kvisor
```

Expected pods:

| Pod | Containers | Description |
|-----|-----------|-------------|
| `castai-kvisor-agent-*` | 3/3 (kvisor, obi, otel-collector) | Per-node DaemonSet |
| `castai-kvisor-controller-*` | 2/2 (controller, otel-collector) | Single Deployment |
| `chi-castai-kvisor-clickhouse-otel-0-0-0` | 2/2 (clickhouse, ch-exporter) | ClickHouse + exporter |
| `castai-kvisor-clickhouse-operator-*` | 2/2 | Altinity operator (if `reliabilityMetrics.operator.enabled=true`) |

### 2. Verify OBI Instrumentation

```bash
POD=$(kubectl get pods -n castai-agent \
  -l app.kubernetes.io/name=castai-kvisor-agent -o name | head -1)

kubectl logs $POD -n castai-agent -c obi | grep 'instrumenting'
```

Expected output:
```
level=INFO msg="instrumenting process" cmd=myapp pid=1234 type=go
```

### 3. Verify OTel Collectors

```bash
# Agent collector
kubectl logs $POD -n castai-agent -c otel-collector --tail=10

# Controller collector
kubectl logs -l app.kubernetes.io/name=castai-kvisor-controller \
  -n castai-agent -c otel-collector --tail=10
```

Should show `Everything is ready. Begin running and processing data.`

### 4. Verify ClickHouse Data

```bash
CH_POD=$(kubectl get pods -n castai-agent \
  -l clickhouse.altinity.com/chi=castai-kvisor-clickhouse -o name | head -1)

# Check tables exist
kubectl exec $CH_POD -n castai-agent -c clickhouse -- \
  clickhouse-client -d metrics -q "SHOW TABLES"

# Check for data (wait 2-3 minutes after installation)
kubectl exec $CH_POD -n castai-agent -c clickhouse -- \
  clickhouse-client -d metrics -q "
    SELECT 'bronze_histograms' as layer, count() FROM otel_metrics_histogram
    UNION ALL
    SELECT 'silver_http', count() FROM reliability_metrics_http
    UNION ALL
    SELECT 'silver_grpc', count() FROM reliability_metrics_grpc
    UNION ALL
    SELECT 'silver_db', count() FROM reliability_metrics_db
    FORMAT PrettyCompact"
```

### 5. Verify ch-exporter

```bash
kubectl logs $CH_POD -n castai-agent -c ch-exporter --tail=20
```

Should show rows being exported:
```
level=info msg="rows exported to CastAI" rows=39 table=reliability_metrics_http
level=info msg="data is synced to CastAI" table=reliability_metrics_http
```

## What Gets Instrumented

OBI automatically discovers and instruments application processes via eBPF (no code changes required):

| Protocol | Metrics | Key Attributes |
|----------|---------|----------------|
| **HTTP** | `http.server.request.duration` | method, status_code, error_type |
| **gRPC** | `rpc.server.duration` | rpc.method, rpc.service, grpc.status_code |
| **Database** | `db.client.operation.duration` | db.system.name, db.operation.name |
| **Messaging** | `messaging.publish.duration`, `messaging.process.duration` | messaging.system, messaging.destination.name |
| **K8s state** | Pod phase, container restarts, deployment availability, HPA pressure | namespace, workload_name, node |

Only **server-side** golden signal metrics are retained. The OTel Collector's `filter/golden-signals` drops client-side metrics (`http.client.request.duration`, `rpc.client.duration`) before they reach ClickHouse — this reduces Bronze write volume by ~59%. OBI instruments both client and server calls, but only server-side metrics measure each workload's own reliability; client-side metrics are redundant because the downstream service already reports its own server metrics.

## Startup Timeline

| Time | Event |
|------|-------|
| 0-30s | OTel collectors start, begin buffering data in sending_queue |
| 30-60s | ClickHouse operator reconciles, StatefulSet pod starts |
| 60-120s | ClickHouse ready, migrate job runs goose schema migrations |
| 60-180s | Collectors drain queues, Bronze data flows into ClickHouse |
| 120-180s | Materialized Views populate Silver tables from Bronze inserts |
| 180s+ | ch-exporter starts polling Silver tables and exporting to CAST AI |

The OTel Collectors buffer up to ~5M data points (10-15 min of data) while waiting for ClickHouse. Transient DNS and connection errors during this window are normal and resolve automatically.

## Resource Consumption

### Per-Component Observed Usage

The table below shows typical resource usage observed in production clusters. Values are **actual usage**, not Kubernetes requests/limits.

| Component | Runs on | CPU (typical) | Memory (typical) | Primary Scaling Factor |
|-----------|---------|--------------|-----------------|----------------------|
| **kvisor agent** | every node | 5–15m | 150–200 MiB | eBPF event rate on the node |
| **OBI** (eBPF instrumenter) | every node | 5–90m | 100–500 MiB | Instrumented processes per node (~27 MiB each) |
| **OTel Collector** (agent) | every node | 2–10m | 50–150 MiB | Metric volume and cardinality on the node |
| **kvisor controller** | once per cluster | 30–80m | 400–600 MiB | Total K8s objects (pods, deployments) |
| **OTel Collector** (controller) | once per cluster | 30–80m | 100–200 MiB | K8s gauge metrics (pod health, HPA, etc.) |
| **ClickHouse** | once per cluster | 200–500m | 1–1.3 GiB | Data volume and background merge pressure |
| **ch-exporter** | once per cluster | <5m | <20 MiB | Silver table rows pending export |

### What Dominates the Footprint

The stack's cost splits into **per-node** (DaemonSet) and **per-cluster** (single-instance) components:

- **Per-node cost** is ~200–400 MiB memory per node across the three agent containers. OBI is the largest contributor — its memory usage depends entirely on how many processes it instruments on each node.
- **Per-cluster cost** is ~2–2.5 GiB memory total (controller + ClickHouse + ch-exporter). This is largely fixed regardless of cluster size.

On a 30-node cluster, expect roughly **8–14 GiB** total memory usage across all components. On a 100-node cluster, **22–42 GiB**. The wide range reflects that OBI memory varies significantly between nodes — a node running 3 services uses ~120 MiB while a node running 18 services may use ~530 MiB.

### OBI Memory Sizing

OBI is the single most important component to size correctly. Each instrumented process consumes ~27 MiB of steady-state memory inside OBI for eBPF maps and metric buffers. Choose a sizing profile that covers the busiest node in your cluster:

| OBI Profile | Memory Request / Limit | Handles Up To |
|-------------|----------------------|---------------|
| small | 128Mi / 256Mi | ~5 processes per node |
| medium | 384Mi / 768Mi | ~15 processes per node |
| large | 512Mi / 1 GiB | ~30 processes per node |
| xlarge | 768Mi / 1.5 GiB | ~50 processes per node |

Run `obi-sizing-report.sh` to see how many processes each node runs and get a profile recommendation. Enable `dynamicSizing: true` to have each node verify at startup that its memory limit is sufficient for its actual process count.

> **📖 See also:** [OBI Sizing Guide](obi-sizing.md) for the full sizing model, dynamic sizing,
> and pod placement strategies to reduce memory variance across nodes.

### ClickHouse Sizing

ClickHouse stores Bronze tables (raw OTel metrics, 4-hour TTL) and Silver tables (1-minute aggregations, 7-day TTL). Disk usage is bounded by the TTLs:

| Cluster Size | Observed Disk Usage (7 days) | Recommended PVC |
|-------------|-----------------------------|-----------------| 
| ≤30 nodes | ~1 GiB | 20–50 GiB |
| 30–100 nodes | 1–3 GiB | 50–100 GiB |
| 100+ nodes | 3–10 GiB | 100–200 GiB |

The default ClickHouse memory limit of 2 GiB is sufficient for clusters up to ~100 nodes. For larger clusters or workloads with high metric cardinality, increase to 4 GiB. Gauge metrics (pod phase, container restarts, resource requests/limits) typically dominate Silver storage volume because they emit one row per container per minute.

### When to Increase Defaults

| Symptom | Component | Action |
|---------|-----------|--------|
| OBI OOMKilled | OBI | Bump to a larger sizing profile or enable `dynamicSizing` |
| `memory_limiter` refusing data in collector logs | Agent OTel Collector | Increase memory limit above 256 MiB |
| Controller collector dropping metrics during churn | Controller OTel Collector | Increase CPU request above 250m |
| ClickHouse merge backlog or slow queries | ClickHouse | Increase memory limit to 4 GiB |
| PVC approaching capacity | ClickHouse | Expand PVC or reduce Silver TTL |

## Monitoring with Prometheus Operator

If your cluster runs [Prometheus Operator](https://github.com/prometheus-operator/prometheus-operator), you can create PodMonitor resources to scrape the reliability metrics components automatically.

### Available PodMonitors

| Component | Values path | Metrics port | Key metrics |
|-----------|------------|-------------|-------------|
| Agent OTel Collector | `agent.reliabilityMetrics.collector.podMonitor` | 8888 | `otelcol_receiver_accepted_metric_points`, `otelcol_exporter_sent_metric_points`, `otelcol_processor_dropped_metric_points`, queue sizes |
| OBI (eBPF instrumenter) | `agent.reliabilityMetrics.obi.internalMetrics` | 6061 | Instrumented process count, eBPF map usage, Go runtime stats |
| Controller OTel Collector | `controller.reliabilityMetrics.collector.podMonitor` | 8889 | Same as agent collector (k8s_cluster receiver pipeline) |
| ch-exporter | `reliabilityMetrics.exporter.podMonitor` | 8080 | Export throughput, ClickHouse query latency, gRPC send errors |

**Note:** OBI internal metrics require two enable flags: `agent.reliabilityMetrics.obi.internalMetrics.enabled` (exposes the `/internal/metrics` endpoint) and `agent.reliabilityMetrics.obi.internalMetrics.podMonitor.enabled` (creates the PodMonitor).

### Enable All PodMonitors

Add these to your values file to enable scraping of all components:

```yaml
agent:
  reliabilityMetrics:
    # OBI settings
    obi:
      internalMetrics:
        enabled: true
        podMonitor:
          enabled: true
          labels:
            release: prometheus
    # Agent OTel Collector
    collector:
      podMonitor:
        enabled: true
        labels:
          release: prometheus   # Match your Prometheus Operator's serviceMonitorSelector

controller:
  reliabilityMetrics:
    collector:
      podMonitor:
        enabled: true
        labels:
          release: prometheus

reliabilityMetrics:
  exporter:
    podMonitor:
      enabled: true
      labels:
        release: prometheus
```

Or via `--set` flags:

```bash
helm upgrade castai-kvisor castai-helm/castai-kvisor \
  -n castai-agent \
  --reset-then-reuse-values \
  --set agent.reliabilityMetrics.obi.internalMetrics.enabled=true \
  --set agent.reliabilityMetrics.obi.internalMetrics.podMonitor.enabled=true \
  --set agent.reliabilityMetrics.collector.podMonitor.enabled=true \
  --set controller.reliabilityMetrics.collector.podMonitor.enabled=true \
  --set reliabilityMetrics.exporter.podMonitor.enabled=true
```

### Prometheus Operator Label Matching

Prometheus Operator uses label selectors to decide which PodMonitors to pick up. If your Prometheus is configured with a `podMonitorSelector` (e.g., `release: prometheus`), add matching labels:

```yaml
podMonitor:
  enabled: true
  labels:
    release: prometheus
```

To check what selector your Prometheus uses:

```bash
kubectl get prometheus -A -o jsonpath='{.items[*].spec.podMonitorSelector}'
```

An empty `podMonitorSelector` means Prometheus picks up all PodMonitors in its namespace.

## Troubleshooting

### OBI: "data refused due to high memory usage"

The OTel Collector's `memory_limiter` processor is refusing data from OBI because the collector is under memory pressure.

```bash
kubectl logs <agent-pod> -n castai-agent -c otel-collector | grep "Refusing data"
```

**Fix:** Increase the agent collector memory limits in your values:
```yaml
agent:
  reliabilityMetrics:
    collector:
      resources:
        requests:
          memory: 256Mi
        limits:
          memory: 512Mi
```

The `memory_limiter` in the collector config (`otel-collector-config.yaml`) should be coordinated with the container limit. The soft limit (`limit_mib - spike_limit_mib`) should be ~60-75% of the container memory limit.

### ch-exporter: "cluster ID not found in metadata header"

The exporter cannot find the cluster ID. This happens when:
1. `castai-agent-metadata` ConfigMap has an empty `CLUSTER_ID` (common on ArgoCD-managed clusters where ArgoCD reverts runtime patches)
2. Neither `castai.clusterID` nor `clusterIdConfigMapRef` is configured

**Fix:** Set the cluster ID directly:
```yaml
reliabilityMetrics:
  castai:
    clusterID: "<your-cluster-id>"
```
Or via `--set reliabilityMetrics.castai.clusterID=<id>`.

### ClickHouse: "Database does not exist"

OTel Collectors log `DB::Exception: Database metrics does not exist`. This is normal during the first 1-2 minutes while the migrate job hasn't run yet.

**If it persists beyond 5 minutes:**
```bash
# Check migrate job status
kubectl get jobs -n castai-agent -l app.kubernetes.io/component=migrate

# Check migrate logs
kubectl logs -l app.kubernetes.io/component=migrate -n castai-agent
```

Common causes: wrong credentials, ClickHouse not ready, PVC still provisioning.

### Connection Errors During Startup

Transient connection errors during the first 2-3 minutes after installation are normal. The OTel Collectors automatically retry and buffer data while ClickHouse starts up (queue covers ~10-15 min). If errors persist beyond 5 minutes, check that ClickHouse is running properly.

### No Metrics in ClickHouse Tables

1. **Check OBI is instrumenting:** `kubectl logs <agent-pod> -c obi | grep instrumenting`
2. **Check collector is receiving:** `kubectl logs <agent-pod> -c otel-collector | grep "Exporting"` (should show batch exports)
3. **Check collector errors:** `kubectl logs <agent-pod> -c otel-collector | grep -i error`
4. **Verify ClickHouse DNS:** The collector connects to `castai-kvisor-clickhouse.castai-agent.svc.cluster.local:9000` -- ensure the Service exists

### ClickHouse Pod Restarts

The ClickHouse pod is managed by the Altinity operator via a ClickHouseInstallation CR (deployed as a Helm hook with `resource-policy: keep`). If the pod restarts:

1. The OTel Collectors automatically retry and buffer data (queue covers ~10-15 min)
2. The ch-exporter resumes from its last checkpoint in `export_progress`
3. No data loss if the restart completes within the queue buffer window

Check operator logs if restarts are frequent:
```bash
kubectl logs -l app=clickhouse-operator -n castai-agent
```

### Migration Job Failed

```bash
kubectl logs -l app.kubernetes.io/component=migrate -n castai-agent
```

The migration job should show successful completion. If it failed, check ClickHouse connectivity, credentials, and logs.

### Namespace-scoped ClickHouse Operator Not Reconciling

If the ClickHouseInstallation CR exists but no ClickHouse pod is created, the operator may not be watching the `castai-agent` namespace. Check operator config:

```bash
# Check operator's watched namespaces
kubectl get deployment -l app=clickhouse-operator --all-namespaces -o yaml | grep -A5 WATCH_NAMESPACES
```

If the operator uses `WATCH_NAMESPACES` env var, ensure `castai-agent` is in the list.

## Uninstalling

### Disable Reliability Metrics (Keep Kvisor)

```bash
helm upgrade castai-kvisor castai-helm/castai-kvisor \
  -n castai-agent \
  --reset-then-reuse-values \
  --set agent.reliabilityMetrics.enabled=false \
  --set controller.reliabilityMetrics.enabled=false \
  --set reliabilityMetrics.enabled=false
```

**Note:** The ClickHouseInstallation CR is retained (`resource-policy: keep`) to preserve data. To fully remove ClickHouse:

```bash
# Delete the ClickHouseInstallation CR
kubectl delete chi castai-kvisor-clickhouse -n castai-agent

# Delete PVCs
kubectl delete pvc -n castai-agent -l clickhouse.altinity.com/chi=castai-kvisor-clickhouse
```

### Full Uninstall

```bash
helm uninstall castai-kvisor -n castai-agent

# Clean up retained resources
kubectl delete chi castai-kvisor-clickhouse -n castai-agent 2>/dev/null
kubectl delete pvc -n castai-agent -l clickhouse.altinity.com/chi=castai-kvisor-clickhouse
```
