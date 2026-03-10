# Kvisor Reliability Metrics Installation Guide

> **ALPHA - NOT FOR PRODUCTION USE**
>
> This feature is currently in alpha and is not intended for production use. APIs, configurations, and functionality may change without notice.

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
- `helm` (3.12+) and `kubectl` installed and configured
- CAST AI account with API key and cluster onboarded to CAST AI
- **Altinity ClickHouse operator**: Either let the chart install it (`reliabilityMetrics.operator.enabled=true`) or ensure one is already running in the cluster (`reliabilityMetrics.operator.enabled=false`)

## Installation

### Option 1: Fresh Installation

```bash
helm dependency update ./charts/kvisor

helm install castai-kvisor ./charts/kvisor \
  -n castai-agent --create-namespace \
  --set castai.apiKey=<your-api-key> \
  --set castai.clusterID=<your-cluster-id> \
  --set castai.grpcAddr=<grpc-endpoint> \
  --set agent.reliabilityMetrics.enabled=true \
  --set controller.reliabilityMetrics.enabled=true \
  --set reliabilityMetrics.enabled=true \
  --set reliabilityMetrics.install.enabled=true \
  --set reliabilityMetrics.exporter.enabled=true
```

### Option 2: Enable on Existing Kvisor

```bash
helm dependency update ./charts/kvisor

helm upgrade castai-kvisor ./charts/kvisor \
  -n castai-agent \
  --reset-then-reuse-values \
  --set agent.reliabilityMetrics.enabled=true \
  --set controller.reliabilityMetrics.enabled=true \
  --set reliabilityMetrics.enabled=true \
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
    # OBI image
    image:
      repository: otel/ebpf-instrument
      tag: "v0.6.0"
    # OBI resources (scales with instrumented processes, ~27 MiB each)
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
      OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS: "true"           # Skip expensive Go uprobe attachment
      OTEL_EBPF_BPF_HIGH_REQUEST_VOLUME: "true"            # Ring-buffer mode for high-throughput nodes

    # OTel Collector sidecar (agent)
    collector:
      enabled: true
      image:
        repository: us-docker.pkg.dev/castai-hub/library/reliability-metrics-otel-collector
        tag: "v0.1.2"
      resources:
        requests:
          memory: 128Mi
        limits:
          memory: 256Mi
      prometheusPort: 9400
      clickhouseExporter:
        enabled: true
        address: "tcp://castai-kvisor-clickhouse.castai-agent.svc.cluster.local:9000"

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
      tag: "v0.3.6"
    resources:
      requests:
        cpu: 50m
        memory: 64Mi
      limits:
        memory: 128Mi

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
| **HTTP** | `http.server.request.duration`, `http.client.request.duration` | method, status_code, error_type |
| **gRPC** | `rpc.server.duration`, `rpc.client.duration` | rpc.method, rpc.service, grpc.status_code |
| **Database** | `db.client.operation.duration` | db.system.name, db.operation.name |
| **Messaging** | `messaging.publish.duration`, `messaging.process.duration` | messaging.system, messaging.destination.name |
| **K8s state** | Pod phase, container restarts, deployment availability, HPA pressure | namespace, workload_name, node |

Only golden signal metrics are retained. The OTel Collector drops all other metrics via `filter/golden-signals` before they reach ClickHouse.

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

## Resource Requirements

Approximate per-component resource consumption:

| Component | CPU (typical) | Memory (typical) | Scales With |
|-----------|-------------|-----------------|-------------|
| OBI (per node) | 5-25m | 100-500 MiB | Number of instrumented processes (~27 MiB each) |
| OTel Collector (per node) | 5-50m | 50-150 MiB | Metric cardinality and volume on the node |
| OTel Collector (controller) | 200-500m | 100-200 MiB | Number of K8s objects in the cluster |
| ClickHouse | 200-500m | 1-4 GiB | Data volume, query load, merge pressure |
| ch-exporter | 5m | 14 MiB | Number of Silver table rows to export |

For clusters with 30+ nodes or high-cardinality workloads, consider increasing the agent OTel Collector memory limit above 256 MiB.

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
helm upgrade castai-kvisor ./charts/kvisor \
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
