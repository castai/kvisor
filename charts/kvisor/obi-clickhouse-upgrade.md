# OBI + In-Cluster ClickHouse Upgrade Guide

Upgrade a cluster from default kvisor (single container, no OBI) to full OBI reliability
metrics with an in-cluster ClickHouse instance and export to mothership.

## Architecture

```
In-Cluster (kvisor)                              Mothership (dev-master)
┌──────────────────────────────────────┐         ┌──────────────────────────────────────┐
│  OBI eBPF ──▶ OTel Collector         │         │  Silver × 5 (ReplicatedReplacingMT)  │
│                  │                    │         │    ▲                                 │
│          ClickHouse (single node)    │         │    │ gRPC/Avro                       │
│  ┌────────────────────────────────┐  │         │    │                                 │
│  │ Bronze (MergeTree, 4h TTL)    │  │         │  metrics-ingestor                    │
│  │  otel_metrics_histogram       │  │         │                                      │
│  │  otel_metrics_gauge           │  │         │  Silver ──▶ Gold MVs ──▶ Views       │
│  │         │ MVs                  │  │         │  (7d TTL)   (90d TTL)               │
│  │         ▼                     │  │         └──────────────────────────────────────┘
│  │ Silver (AggregatingMT, 7d)   │  │
│  │  reliability_metrics_http     │──┼── ch-exporter ──▶
│  │  reliability_metrics_grpc     │  │
│  │  reliability_metrics_db       │  │
│  │  reliability_metrics_messaging│  │
│  │  reliability_metrics_gauge    │  │
│  └────────────────────────────────┘  │
└──────────────────────────────────────┘
```

**Database:** `metrics` (both in-cluster and mothership)

**Migrations (in-cluster, goose):**

| File | Content |
|------|---------|
| `001_bronze_tables.sql` | Raw OTLP tables (histogram + gauge) |
| `002_silver_tables.sql` | 5 silver tables (AggregatingMergeTree) |
| `003_bronze_to_silver_mvs.sql` | 5 bronze→silver MVs with `cityHash64` pk |
| `004_export_progress.sql` | Cursor tracking for ch-exporter sidecar |

**Mothership migration (`000034_add_reliability_metrics`):**

| Layer | Objects |
|-------|---------|
| Silver | 5 local + 5 distributed (ReplicatedReplacingMergeTree, 7d TTL) |
| Gold | `reliability_gold_reporting_overview` (ReplicatedAggregatingMergeTree, 90d TTL) |
| MVs | 4 silver→gold (HTTP/gRPC/DB/Messaging → overview) |
| Views | `reliability_v_reporting_overview` (error rates, avg/max latency, RPS) |

## Prerequisites

- Cluster onboarded to CAST AI mothership with default kvisor running
- `helm`, `kubectl` configured with cluster context
- Migration image available in a registry accessible by the cluster

> **CRDs**: The Altinity ClickHouse operator CRDs (v0.26.0) are bundled in
> `templates/clickhouse-operator-crd.yaml` and installed automatically by Helm when
> `clickhouse.operator.enabled=true`. No manual `kubectl apply` needed.
> Note: Helm does not auto-upgrade CRDs on `helm upgrade`. If upgrading the operator
> version, apply the new CRDs manually first:
> `kubectl apply -f https://raw.githubusercontent.com/Altinity/clickhouse-operator/<version>/deploy/operator/parts/crd.yaml`

## Step 1: obi-values.yaml

The values file is already at `charts/kvisor/obi-values.yaml` and is ready to use.
All commands below reference it via `-f charts/kvisor/obi-values.yaml`.

## Step 2: Deploy

A single `helm upgrade` deploys everything at once. No two-pass deployment or manual
restarts are needed because:

- The **OTel ClickHouse exporter** has `create_schema: false` (schema is managed by goose
  migrations, not by the exporter). This is critical — without it, the exporter runs a
  synchronous DDL on startup that crashes if ClickHouse DNS is not yet resolvable.
  With `create_schema: false` plus `retry_on_failure` (infinite retry) and `sending_queue`
  (in-memory buffer), the collector starts healthy, passes liveness probes, and buffers
  data while ClickHouse is starting up.
- The **migration Job** (Helm post-upgrade hook) retries ClickHouse connectivity for up to
  60 seconds (30 attempts × 2s) before running migrations.
- The **Secret** for ClickHouse credentials is rendered in the same Helm release and is
  available to pods immediately.

**Set shell variables:**

```bash
export CONTEXT="gke_engineering-test-353509_europe-west3_kvisor-obi-test"
export NAMESPACE="castai-agent"
export RELEASE="castai-kvisor"
export CH_POD="chi-castai-kvisor-clickhouse-otel-0-0-0"
```

**Deploy:**

```bash
helm upgrade $RELEASE ./charts/kvisor -n $NAMESPACE \
  --kube-context $CONTEXT \
  --timeout 10m \
  -f charts/kvisor/obi-values.yaml \
  --set castai.apiKey=<api-key> \
  --set castai.clusterID=1e59b18a-f20e-4d7a-ba61-aff2636552a1 \
  --set castai.grpcAddr=kvisor.dev-master.cast.ai:443 \
  --set agent.extraArgs.netflow-enabled=true \
  --set controller.extraArgs.image-scan-enabled=true \
  --set controller.extraArgs.kube-bench-cloud-provider=gke \
  --set controller.extraArgs.kube-bench-enabled=true \
  --set controller.extraArgs.kube-linter-enabled=true
```

**Wait for ClickHouse to be ready** (optional — the collectors handle this automatically,
but useful for validation):

```bash
kubectl wait pod -l clickhouse.altinity.com/chi=castai-kvisor-clickhouse \
  -n $NAMESPACE --context $CONTEXT \
  --for=condition=Ready --timeout=300s
```

> **Important:** Do NOT use `--reuse-values` with this upgrade. The new chart has nested
> values (`clickhouse.external`, `clickhouse.operator.image`, etc.) that don't exist in
> the stored release values and will cause nil pointer template errors.

### Startup Timeline

| Time | What happens |
|------|-------------|
| t=0s | Helm applies all manifests: operator, CHI CR, secrets, agent/controller pods, configmaps |
| t=5s | OTel collectors start, pass health probes, begin buffering data in sending_queue |
| t=30-120s | ClickHouse operator reconciles, StatefulSet + PVC created, CH pod starts |
| t=60-180s | ClickHouse ready, collectors drain queue, data flows |
| t=post-install hook | Migration Job runs, creates schema (retries up to 30 attempts × 2s) |

## Step 3: Validate Deployment

### 3.1 Pod Status

All pods should be Running with the correct container count.

```bash
kubectl get pods -n $NAMESPACE --context $CONTEXT
```

Expected:
- `castai-kvisor-agent-*` -- `3/3 Running` (kvisor-agent + obi + otel-collector)
- `castai-kvisor-controller-*` -- `2/2 Running` (controller + otel-collector)
- `chi-castai-kvisor-clickhouse-otel-0-0-0` -- `2/2 Running` (clickhouse + ch-exporter)
- `castai-kvisor-clickhouse-operator-*` -- `2/2 Running`
- `castai-kvisor-clickhouse-migrate-*` -- `0/1 Completed`

### 3.2 OBI Logs

Check that OBI is instrumenting processes:

```bash
# Pick any agent pod
POD=$(kubectl get pods -n $NAMESPACE --context $CONTEXT \
  -l app.kubernetes.io/name=castai-kvisor-agent -o name | head -1)

kubectl logs $POD -n $NAMESPACE --context $CONTEXT -c obi | grep 'instrumenting'
```

Expected output (one line per instrumented process on that node):
```
time=... level=INFO msg="instrumenting process" component=discover.traceAttacher cmd=... pid=... type=go
```

**Benign warnings to ignore:**
- `falling back to IMDSv1` -- Expected on non-AWS clusters
- `error reading itab section in Go program` -- Some Go binaries lack symbol tables; auto-instrumentation still works
- `creating OTEL namespace in bpffs failed` -- bpffs not mounted; log enricher disabled but eBPF instrumentation works

### 3.3 OTel Collector Logs

Verify both agent and controller collectors are running and have no errors:

```bash
# Agent collector
kubectl logs $POD -n $NAMESPACE --context $CONTEXT -c otel-collector --tail=5
```

Should end with:
```
... info service@.../service.go:264 Everything is ready. Begin running and processing data.
```

Check for errors:
```bash
kubectl logs $POD -n $NAMESPACE --context $CONTEXT -c otel-collector | \
  grep -iE 'error|drop|refused|timeout|retry' | grep -v 'filter configured'
```

Should be empty. Transient `connection refused` errors to ClickHouse during startup are
normal — the collector retries automatically and drains its queue once CH is ready.

```bash
# Controller collector
kubectl logs -l app.kubernetes.io/name=castai-kvisor-controller \
  -n $NAMESPACE --context $CONTEXT -c otel-collector --tail=5
```

Should show `k8s_cluster` receiver started and `Everything is ready`.

### 3.4 ClickHouse Logs

```bash
kubectl logs $CH_POD -n $NAMESPACE --context $CONTEXT -c clickhouse --tail=5
```

Should show:
```
... Listening for http://0.0.0.0:8123
... Listening for native protocol (tcp): 0.0.0.0:9000
... Ready for connections.
```

### 3.5 Migration Logs

```bash
kubectl logs -l app.kubernetes.io/component=clickhouse-migrate \
  -n $NAMESPACE --context $CONTEXT
```

Expected:
```
... INFO ensuring database exists database=metrics
... INFO connected to ClickHouse addr=castai-kvisor-clickhouse...:9000 database=metrics
... INFO running migrations: up
... OK   001_bronze_tables.sql (...)
... OK   002_silver_tables.sql (...)
... OK   003_bronze_to_silver_mvs.sql (...)
... OK   004_export_progress.sql (...)
... goose: successfully migrated database to version: 4
... INFO migrations completed successfully
```

### 3.6 CH Exporter Logs

The exporter sidecar runs inside the ClickHouse pod and exports silver data to mothership:

```bash
kubectl logs $CH_POD -n $NAMESPACE --context $CONTEXT -c ch-exporter --tail=20
```

Expected: periodic export logs showing rows exported per table. If you see
`no new rows` that's normal when there's no new data since last export.

## Step 4: Validate Data Flow

### 4.1 Check Tables Exist

```bash
kubectl exec $CH_POD -n $NAMESPACE --context $CONTEXT -c clickhouse -- \
  clickhouse-client -d metrics -q "
    SELECT name, engine
    FROM system.tables
    WHERE database = 'metrics'
    ORDER BY name
    FORMAT PrettyCompact"
```

Expected tables:

| Table | Engine | Description |
|-------|--------|-------------|
| `otel_metrics_histogram` | MergeTree | Bronze: OBI latency/duration histograms (4h TTL) |
| `otel_metrics_gauge` | MergeTree | Bronze: k8s reliability gauges (4h TTL) |
| `reliability_metrics_http` | AggregatingMergeTree | Silver: HTTP request aggregates (7d TTL) |
| `reliability_metrics_grpc` | AggregatingMergeTree | Silver: gRPC request aggregates (7d TTL) |
| `reliability_metrics_db` | AggregatingMergeTree | Silver: DB client aggregates (7d TTL) |
| `reliability_metrics_messaging` | AggregatingMergeTree | Silver: messaging aggregates (7d TTL) |
| `reliability_metrics_gauge` | AggregatingMergeTree | Silver: k8s gauge aggregates (7d TTL) |
| `reliability_mv_bronze_to_silver_*` | MaterializedView | 5 bronze→silver MVs |
| `export_progress` | ReplacingMergeTree | Exporter cursor tracking |

### 4.2 Check Bronze Data (Raw OTLP)

Wait 2-3 minutes after deployment, then:

```bash
kubectl exec $CH_POD -n $NAMESPACE --context $CONTEXT -c clickhouse -- \
  clickhouse-client -d metrics -q "
    SELECT
      'histogram' as tbl, count() as rows, uniqExact(MetricName) as metrics,
      min(TimeUnix) as earliest, max(TimeUnix) as latest
    FROM otel_metrics_histogram
    UNION ALL
    SELECT
      'gauge', count(), uniqExact(MetricName),
      min(TimeUnix), max(TimeUnix)
    FROM otel_metrics_gauge
    FORMAT PrettyCompact"
```

- `histogram` should have rows with metrics like `http.server.request.duration`, `rpc.server.duration`
- `gauge` should have rows with metrics like `k8s.container.restarts`, `k8s.pod.phase`
- `latest` timestamps should be within the last few minutes

### 4.3 Check Histogram Metrics by Service

```bash
kubectl exec $CH_POD -n $NAMESPACE --context $CONTEXT -c clickhouse -- \
  clickhouse-client -d metrics -q "
    SELECT
      ServiceName as service_name,
      MetricName,
      count() as cnt
    FROM otel_metrics_histogram
    GROUP BY service_name, MetricName
    ORDER BY service_name, cnt DESC
    FORMAT PrettyCompact"
```

Should show services discovered by OBI (e.g., `castai-kvisor-controller`,
`castai-pod-mutator`) with golden signal metrics.

### 4.4 Check Silver Layer (Aggregated)

```bash
kubectl exec $CH_POD -n $NAMESPACE --context $CONTEXT -c clickhouse -- \
  clickhouse-client -d metrics -q "
    SELECT 'http' as tbl, count() as rows FROM reliability_metrics_http
    UNION ALL SELECT 'grpc', count() FROM reliability_metrics_grpc
    UNION ALL SELECT 'db', count() FROM reliability_metrics_db
    UNION ALL SELECT 'messaging', count() FROM reliability_metrics_messaging
    UNION ALL SELECT 'gauge', count() FROM reliability_metrics_gauge
    FORMAT PrettyCompact"
```

- `http` and `grpc` should have rows if OBI discovered HTTP/gRPC services
- `gauge` should have rows from the controller's k8s reliability gauges
- `db` and `messaging` will be 0 unless workloads make DB or messaging calls

### 4.5 Sample Silver HTTP Data

```bash
kubectl exec $CH_POD -n $NAMESPACE --context $CONTEXT -c clickhouse -- \
  clickhouse-client -d metrics -q "
    SELECT
      minute, service_name, k8s_deployment, http_method, http_status_code,
      total_count, total_sum, sample_count
    FROM reliability_metrics_http
    ORDER BY minute DESC
    LIMIT 10
    FORMAT PrettyCompact"
```

### 4.6 Check Export Progress

Verify the exporter cursor is advancing:

```bash
kubectl exec $CH_POD -n $NAMESPACE --context $CONTEXT -c clickhouse -- \
  clickhouse-client -d metrics -q "
    SELECT
      table_name,
      last_exported_time,
      last_exported_pk
    FROM export_progress FINAL
    FORMAT PrettyCompact"
```

`last_exported_time` should be recent if the exporter is running. If it's still at
`1970-01-01`, the exporter hasn't started exporting yet.

## Step 5: Validate Mothership Data

After the ch-exporter sidecar has been running for a few minutes, verify data arrived
on the mothership.

**Set mothership variables:**

```bash
export MS_CONTEXT="dev-master"
export MS_NAMESPACE="custom-metrics"
export MS_POD="chi-custom-metrics-clickhouse-cmetrics-0-0-0"
```

### 5.1 Check Silver Tables on Mothership

```bash
kubectl --context=$MS_CONTEXT -n $MS_NAMESPACE \
  exec $MS_POD -c clickhouse-pod -- clickhouse-client --query "
    SELECT 'http' as tbl, count() as rows, min(minute) as min_ts, max(minute) as max_ts
    FROM metrics.reliability_metrics_http
    UNION ALL SELECT 'grpc', count(), min(minute), max(minute)
    FROM metrics.reliability_metrics_grpc
    UNION ALL SELECT 'db', count(), min(minute), max(minute)
    FROM metrics.reliability_metrics_db
    UNION ALL SELECT 'messaging', count(), min(minute), max(minute)
    FROM metrics.reliability_metrics_messaging
    UNION ALL SELECT 'gauge', count(), min(minute), max(minute)
    FROM metrics.reliability_metrics_gauge
    FORMAT PrettyCompact"
```

### 5.2 Check Gold Overview Table

```bash
kubectl --context=$MS_CONTEXT -n $MS_NAMESPACE \
  exec $MS_POD -c clickhouse-pod -- clickhouse-client --query "
    SELECT count() as rows, min(five_min) as min_ts, max(five_min) as max_ts
    FROM metrics.reliability_gold_reporting_overview
    FORMAT PrettyCompact"
```

Gold rows are created automatically by the 4 silver→gold MVs whenever silver data is
inserted.

### 5.3 Query the Convenience View

```bash
kubectl --context=$MS_CONTEXT -n $MS_NAMESPACE \
  exec $MS_POD -c clickhouse-pod -- clickhouse-client --query "
    SELECT *
    FROM metrics.reliability_v_reporting_overview
    ORDER BY five_min DESC
    LIMIT 5
    FORMAT Vertical"
```

This shows computed metrics: `error_rate`, `total_rps`, `*_avg_latency_ms`,
`*_max_latency_ms` per (namespace, service, deployment, 5-min window).

### 5.4 List All Reliability Objects on Mothership

```bash
kubectl --context=$MS_CONTEXT -n $MS_NAMESPACE \
  exec $MS_POD -c clickhouse-pod -- clickhouse-client --query "
    SELECT name, engine
    FROM system.tables
    WHERE database = 'metrics' AND name LIKE 'reliability%'
    ORDER BY name
    FORMAT PrettyCompact"
```

Expected (17 objects):

| Object | Engine |
|--------|--------|
| `reliability_gold_reporting_overview` | Distributed |
| `reliability_gold_reporting_overview_local` | ReplicatedAggregatingMergeTree |
| `reliability_metrics_http` / `_local` | Distributed / ReplicatedReplacingMergeTree |
| `reliability_metrics_grpc` / `_local` | Distributed / ReplicatedReplacingMergeTree |
| `reliability_metrics_db` / `_local` | Distributed / ReplicatedReplacingMergeTree |
| `reliability_metrics_messaging` / `_local` | Distributed / ReplicatedReplacingMergeTree |
| `reliability_metrics_gauge` / `_local` | Distributed / ReplicatedReplacingMergeTree |
| `reliability_mv_silver_http_to_gold_overview` | MaterializedView |
| `reliability_mv_silver_grpc_to_gold_overview` | MaterializedView |
| `reliability_mv_silver_db_to_gold_overview` | MaterializedView |
| `reliability_mv_silver_messaging_to_gold_overview` | MaterializedView |
| `reliability_v_reporting_overview` | View |

## Step 6: Schema Management

### In-Cluster (kvisor)

Migrations live in `cmd/clickhouse-migrate/migrations/otel/` and are run by goose.
To add a new migration:

```bash
# Create new file following goose naming convention
vim cmd/clickhouse-migrate/migrations/otel/005_new_feature.sql
```

```sql
-- +goose Up
CREATE TABLE IF NOT EXISTS metrics.new_table ( ... )
ENGINE = AggregatingMergeTree ...;

-- +goose Down
DROP TABLE IF EXISTS metrics.new_table;
```

Build and push:
```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/clickhouse-migrate-amd64 ./cmd/clickhouse-migrate
docker build --platform linux/amd64 -t eu.gcr.io/engineering-test-353509/kvisor-clickhouse-migrate:<tag> \
  --build-arg TARGETARCH=amd64 . -f Dockerfile.clickhouse-migrate
docker push eu.gcr.io/engineering-test-353509/kvisor-clickhouse-migrate:<tag>
```

Update `obi-values.yaml` with the new tag and redeploy. The migration Job detects
already-applied migrations and only runs new ones.

### Mothership (metrics-ingestor)

The mothership schema lives in `services/metrics-ingestor/clickhouse/migrations/000034_add_reliability_metrics.up.sql`.
It is applied via the metrics-ingestor's standard migration flow.

To apply manually on dev-master:

```bash
kubectl --context=$MS_CONTEXT -n $MS_NAMESPACE \
  exec $MS_POD -c clickhouse-pod -- clickhouse-client --multiquery --query "$(cat \
  /path/to/000034_add_reliability_metrics.up.sql)"
```

### Key Schema Differences: In-Cluster vs Mothership

| Aspect | In-Cluster | Mothership |
|--------|-----------|------------|
| Engine (silver) | `AggregatingMergeTree` | `ReplicatedReplacingMergeTree()` |
| `bucket_counts` | `AggregateFunction(sumForEach, Array(UInt64))` | `Array(UInt64)` |
| `explicit_bounds` | `SimpleAggregateFunction(anyLast, Array(Float64))` | `Array(Float64)` |
| Replication | Single node, no replication | `ON CLUSTER '{cluster}'` |
| Storage policy | Default | `move_to_gcs` |
| Gold layer | None (silver only) | `reliability_gold_reporting_overview` (90d TTL) |
| Export cursor | `export_progress` table | N/A (ingestor handles) |

The `bucket_counts` difference is intentional: in-cluster uses `AggregateFunction` for
correct background merges in `AggregatingMergeTree`. The ch-exporter finalizes it with
`sumForEachMerge(bucket_counts)` in the SELECT (baked into `export_progress.columns`),
so mothership receives plain `Array(UInt64)`.

## Known Limitations

- **`min_value`/`max_value` are always 0**: OTLP histogram `Min`/`Max` fields are optional
  and OBI does not populate them. These columns exist for forward compatibility. For max
  latency estimation, use the highest non-zero bucket boundary.
- **Histograms and gauge data not in gold table**: `bucket_counts`/`explicit_bounds` are
  plain arrays that can't merge correctly in `AggregatingMergeTree`. Gauge data has a
  pod-to-deployment mapping gap. Both are queried from silver at read time.
- **Delta temporality zero rows**: OBI uses delta temporality (`AggregationTemporality=1`).
  The OTEL collector emits data points even when there's no activity in a window, resulting
  in rows with `total_count=0`. These don't affect correctness — `sum(total_count)` in gold
  MVs correctly aggregates only actual request counts.

## Troubleshooting

### Helm release stuck in `pending-upgrade`

```bash
helm history $RELEASE -n $NAMESPACE --kube-context $CONTEXT --max 5
# Find the last "deployed" revision number, then:
helm rollback $RELEASE <revision-number> -n $NAMESPACE --kube-context $CONTEXT
```

### ClickHouse CrashLoopBackOff

Check logs:
```bash
kubectl logs $CH_POD -n $NAMESPACE --context $CONTEXT -c clickhouse --previous
```

Common causes:
- **`Profile clickhouse_operator was not found`** -- The `clickhouse_operator/readonly: 0` profile is missing from the CHI spec
- **`SSL Exception: no certificate file`** -- The `files.disable_ssl.xml` override is missing from the CHI spec
- **`Listen [::]:9000 failed: Address family not supported`** -- IPv6 not available; ensure `listen_host: "0.0.0.0"` (not `"::"`)

### OTel collector CrashLoopBackOff: `failed to start "clickhouse" exporter: create database`

The ClickHouse exporter's `create_schema` setting (default `true`) runs a synchronous DDL
on startup. If the ClickHouse Service DNS is not yet resolvable (operator hasn't created
it yet), the exporter crashes with `no such host` and the collector exits.

**Fix:** Ensure `create_schema: false` is set in the OTel collector config for both agent
and controller ClickHouse exporters. Schema creation is handled by the migration Job
instead. This setting is already configured in the chart templates.

### OTel collector `connection refused` to ClickHouse

The collector retries ClickHouse indefinitely (`max_elapsed_time: 0s`) and buffers data
in a `sending_queue`. Normally no action is needed — once ClickHouse is ready, the queue
drains automatically.

If the collector has been running for 10+ minutes and still shows `connection refused`:
1. Verify ClickHouse pod is Running: `kubectl get pod $CH_POD -n $NAMESPACE --context $CONTEXT`
2. Verify the ClickHouse service exists: `kubectl get svc -n $NAMESPACE --context $CONTEXT | grep click`
3. If ClickHouse is healthy but collectors still fail, restart:
```bash
kubectl rollout restart daemonset/castai-kvisor-agent -n $NAMESPACE --context $CONTEXT
kubectl rollout restart deployment/castai-kvisor-controller -n $NAMESPACE --context $CONTEXT
```

### Migration Job `no such host`

The ClickHouse service DNS name doesn't match. Verify the service exists:
```bash
kubectl get svc -n $NAMESPACE --context $CONTEXT | grep click
```

The serviceTemplate creates `castai-kvisor-clickhouse` (ClusterIP) -- the migration
should connect to `castai-kvisor-clickhouse.<namespace>.svc.cluster.local:9000`.

### No data in ClickHouse after 5 minutes

1. Check OBI is instrumenting processes: `kubectl logs $POD -n $NAMESPACE --context $CONTEXT -c obi | grep instrumenting`
2. Check collector has no errors: `kubectl logs $POD -n $NAMESPACE --context $CONTEXT -c otel-collector | grep -i error`
3. Verify ClickHouse is accepting connections: `kubectl logs $CH_POD -n $NAMESPACE --context $CONTEXT -c clickhouse | grep "Ready for connections"`
4. Check ClickHouse service is reachable from within the cluster:
   ```bash
   kubectl run ch-test --rm -it --image=busybox --restart=Never \
     -n $NAMESPACE --context $CONTEXT -- \
     wget -qO- http://castai-kvisor-clickhouse.castai-agent.svc.cluster.local:8123/ping
   ```
   Should return `Ok.`

### No data on mothership

1. Check ch-exporter logs: `kubectl logs $CH_POD -n $NAMESPACE --context $CONTEXT -c ch-exporter --tail=30`
2. Check export cursor is advancing (see Step 4.6)
3. Verify the exporter gRPC address matches mothership: check `clickhouse.exporter.grpcAddr` in values
