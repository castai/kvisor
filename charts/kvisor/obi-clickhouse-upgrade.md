# OBI + In-Cluster ClickHouse Upgrade Guide

Upgrade a cluster from default kvisor (single container, no OBI) to full OBI reliability
metrics with an in-cluster ClickHouse instance.

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
  --set castai.apiKey=13153335c377efa94bce6c3d123ea65e3f45bad9d222d39c9dbb328c36122089 \
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
- `chi-castai-kvisor-clickhouse-otel-0-0-0` -- `1/1 Running`
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
kubectl logs chi-castai-kvisor-clickhouse-otel-0-0-0 -n $NAMESPACE --context $CONTEXT --tail=5
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
... INFO ensuring database exists database=kvisor
... INFO connected to ClickHouse addr=castai-kvisor-clickhouse...:9000 database=kvisor
... INFO running migrations: up
... OK   001_bronze_tables.sql (...)
... OK   002_silver_http_grpc.sql (...)
... OK   003_silver_db_messaging_gauge.sql (...)
... goose: successfully migrated database to version: 3
... INFO migrations completed successfully
```

## Step 4: Validate Data Flow

### 4.1 Check Tables Exist

```bash
kubectl exec chi-castai-kvisor-clickhouse-otel-0-0-0 \
  -n $NAMESPACE --context $CONTEXT -- \
  clickhouse-client --user kvisor --password kvisor -d otel -q "
    SELECT name, engine, total_rows, total_bytes
    FROM system.tables
    WHERE database = 'otel'
    ORDER BY name
    FORMAT PrettyCompact"
```

Expected tables:

| Table | Engine | Description |
|-------|--------|-------------|
| `otel_metrics_histogram` | MergeTree | Bronze: OBI latency/duration histograms |
| `otel_metrics_gauge` | MergeTree | Bronze: k8s reliability gauges |
| `otel_metrics_sum` | MergeTree | Bronze: sum metrics (may be empty) |
| `otel_metrics_exponential_histogram` | MergeTree | Bronze: exp histograms (usually empty) |
| `otel_metrics_summary` | MergeTree | Bronze: summary metrics (usually empty) |
| `silver_http_1m` | AggregatingMergeTree | Silver: HTTP request aggregates |
| `silver_grpc_1m` | AggregatingMergeTree | Silver: gRPC request aggregates |
| `silver_gauge_1m` | AggregatingMergeTree | Silver: k8s gauge aggregates |
| `silver_db_1m` | AggregatingMergeTree | Silver: DB client aggregates |
| `silver_messaging_1m` | AggregatingMergeTree | Silver: messaging aggregates |
| `mv_bronze_to_silver_*` | MaterializedView | MVs powering bronze-to-silver |

### 4.2 Check Bronze Data (Raw OTLP)

Wait 2-3 minutes after deployment, then:

```bash
kubectl exec chi-castai-kvisor-clickhouse-otel-0-0-0 \
  -n $NAMESPACE --context $CONTEXT -- \
  clickhouse-client --user kvisor --password kvisor -d otel -q "
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
kubectl exec chi-castai-kvisor-clickhouse-otel-0-0-0 \
  -n $NAMESPACE --context $CONTEXT -- \
  clickhouse-client --user kvisor --password kvisor -d otel -q "
    SELECT
      ResourceAttributes['service.name'] as service_name,
      MetricName,
      count() as cnt
    FROM otel_metrics_histogram
    GROUP BY service_name, MetricName
    ORDER BY service_name, cnt DESC
    FORMAT PrettyCompact"
```

Should show services discovered by OBI (e.g., `castai-workload-autoscaler`,
`castai-pod-mutator`, `castai-kvisor-controller`) with golden signal metrics.

### 4.4 Check Gauge Metrics (Reliability)

```bash
kubectl exec chi-castai-kvisor-clickhouse-otel-0-0-0 \
  -n $NAMESPACE --context $CONTEXT -- \
  clickhouse-client --user kvisor --password kvisor -d otel -q "
    SELECT MetricName, count() as cnt
    FROM otel_metrics_gauge
    GROUP BY MetricName
    ORDER BY cnt DESC
    FORMAT PrettyCompact"
```

Expected metrics from the controller's `k8s_cluster` receiver:
- `k8s.container.restarts`, `k8s.container.ready`, `k8s.pod.phase`
- `k8s.deployment.desired`, `k8s.deployment.available`
- `k8s.daemonset.*`, `k8s.statefulset.*`, `k8s.replicaset.*`
- `k8s.node.condition_ready`
- `k8s.container.cpu_request`, `k8s.container.memory_limit`, etc.

### 4.5 Check Silver Layer (Aggregated)

```bash
kubectl exec chi-castai-kvisor-clickhouse-otel-0-0-0 \
  -n $NAMESPACE --context $CONTEXT -- \
  clickhouse-client --user kvisor --password kvisor -d otel -q "
    SELECT
      'silver_http_1m'  as tbl, count() as rows FROM silver_http_1m
    UNION ALL SELECT
      'silver_grpc_1m', count() FROM silver_grpc_1m
    UNION ALL SELECT
      'silver_gauge_1m', count() FROM silver_gauge_1m
    UNION ALL SELECT
      'silver_db_1m', count() FROM silver_db_1m
    UNION ALL SELECT
      'silver_messaging_1m', count() FROM silver_messaging_1m
    FORMAT PrettyCompact"
```

- `silver_http_1m` and `silver_grpc_1m` should have rows if OBI discovered HTTP/gRPC services
- `silver_gauge_1m` should have rows from the controller's k8s reliability gauges
- `silver_db_1m` and `silver_messaging_1m` will be 0 unless workloads make DB or messaging calls

### 4.6 Sample Silver HTTP Data

```bash
kubectl exec chi-castai-kvisor-clickhouse-otel-0-0-0 \
  -n $NAMESPACE --context $CONTEXT -- \
  clickhouse-client --user kvisor --password kvisor -d otel -q "
    SELECT
      service_name, http_method, http_status_code, count() as cnt
    FROM silver_http_1m
    GROUP BY service_name, http_method, http_status_code
    ORDER BY cnt DESC
    LIMIT 20
    FORMAT PrettyCompact"
```

## Step 5: Simulate Data Flow (DB and Messaging Metrics)

The `silver_db_1m` and `silver_messaging_1m` tables will be empty unless the cluster runs
workloads that make database or messaging calls instrumented by OBI. This section shows
how to inject synthetic bronze data to verify the full MV pipeline works end-to-end.

### How the Pipeline Works

```
Bronze (otel_metrics_histogram)
  │
  ├── mv_bronze_to_silver_http     ──▶  silver_http_1m       (WHERE MetricName IN http.*.request.duration)
  ├── mv_bronze_to_silver_grpc     ──▶  silver_grpc_1m       (WHERE MetricName IN rpc.*.duration)
  ├── mv_bronze_to_silver_db       ──▶  silver_db_1m         (WHERE MetricName = db.client.operation.duration)
  └── mv_bronze_to_silver_messaging──▶  silver_messaging_1m  (WHERE MetricName IN messaging.*.duration)
```

Materialized Views fire on INSERT into the source table. Inserting rows with the correct
`MetricName` and `Attributes` keys into `otel_metrics_histogram` will automatically
populate the corresponding silver tables.

### 5.1 Inject Synthetic DB Client Metrics

This simulates a PostgreSQL database client generating `db.client.operation.duration`
histogram data, as if OBI had instrumented a Go service making DB calls.

```bash
kubectl exec $CH_POD -n $NAMESPACE --context $CONTEXT -- \
  clickhouse-client --user kvisor --password kvisor -d otel -q "
INSERT INTO otel_metrics_histogram (
    ResourceAttributes, ResourceSchemaUrl, ScopeName, ScopeVersion,
    ScopeAttributes, ScopeDroppedAttrCount, ScopeSchemaUrl,
    ServiceName, MetricName, MetricDescription, MetricUnit,
    Attributes, StartTimeUnix, TimeUnix,
    Count, Sum, BucketCounts, ExplicitBounds,
    Flags, Min, Max, AggregationTemporality
) VALUES
-- Simulated: orders-api SELECT queries against PostgreSQL
(
    {'service.name':'orders-api','k8s.namespace.name':'production','k8s.deployment.name':'orders-api','k8s.node.name':'node-1'},
    '', 'obi', '1.0', {}, 0, '',
    'orders-api', 'db.client.operation.duration', 'Duration of database client operations', 's',
    {'db.system.name':'postgresql','db.operation.name':'SELECT','error.type':''},
    now64(9) - 60, now64(9),
    150, 4.5, [10,30,40,35,20,10,5,0,0,0,0], [0.005,0.01,0.025,0.05,0.075,0.1,0.25,0.5,0.75,1.0],
    0, 0.001, 0.22, 1
),
-- Simulated: orders-api INSERT queries
(
    {'service.name':'orders-api','k8s.namespace.name':'production','k8s.deployment.name':'orders-api','k8s.node.name':'node-1'},
    '', 'obi', '1.0', {}, 0, '',
    'orders-api', 'db.client.operation.duration', 'Duration of database client operations', 's',
    {'db.system.name':'postgresql','db.operation.name':'INSERT','error.type':''},
    now64(9) - 60, now64(9),
    45, 2.25, [5,10,15,10,3,2,0,0,0,0,0], [0.005,0.01,0.025,0.05,0.075,0.1,0.25,0.5,0.75,1.0],
    0, 0.002, 0.09, 1
),
-- Simulated: orders-api queries with errors
(
    {'service.name':'orders-api','k8s.namespace.name':'production','k8s.deployment.name':'orders-api','k8s.node.name':'node-1'},
    '', 'obi', '1.0', {}, 0, '',
    'orders-api', 'db.client.operation.duration', 'Duration of database client operations', 's',
    {'db.system.name':'postgresql','db.operation.name':'SELECT','error.type':'timeout'},
    now64(9) - 60, now64(9),
    3, 3.0, [0,0,0,0,0,0,0,0,0,1,2], [0.005,0.01,0.025,0.05,0.075,0.1,0.25,0.5,0.75,1.0],
    0, 0.8, 1.5, 1
),
-- Simulated: payments-service Redis calls
(
    {'service.name':'payments-service','k8s.namespace.name':'production','k8s.deployment.name':'payments-service','k8s.node.name':'node-2'},
    '', 'obi', '1.0', {}, 0, '',
    'payments-service', 'db.client.operation.duration', 'Duration of database client operations', 's',
    {'db.system.name':'redis','db.operation.name':'GET','error.type':''},
    now64(9) - 60, now64(9),
    500, 0.5, [400,80,15,5,0,0,0,0,0,0,0], [0.005,0.01,0.025,0.05,0.075,0.1,0.25,0.5,0.75,1.0],
    0, 0.0001, 0.04, 1
)"
```

### 5.2 Inject Synthetic Messaging Metrics

This simulates Kafka producer/consumer latencies via `messaging.publish.duration` and
`messaging.process.duration`.

```bash
kubectl exec $CH_POD -n $NAMESPACE --context $CONTEXT -- \
  clickhouse-client --user kvisor --password kvisor -d otel -q "
INSERT INTO otel_metrics_histogram (
    ResourceAttributes, ResourceSchemaUrl, ScopeName, ScopeVersion,
    ScopeAttributes, ScopeDroppedAttrCount, ScopeSchemaUrl,
    ServiceName, MetricName, MetricDescription, MetricUnit,
    Attributes, StartTimeUnix, TimeUnix,
    Count, Sum, BucketCounts, ExplicitBounds,
    Flags, Min, Max, AggregationTemporality
) VALUES
-- Simulated: notification-service publishing to Kafka
(
    {'service.name':'notification-service','k8s.namespace.name':'production','k8s.deployment.name':'notification-service','k8s.node.name':'node-1'},
    '', 'obi', '1.0', {}, 0, '',
    'notification-service', 'messaging.publish.duration', 'Duration of message publish', 's',
    {'messaging.system':'kafka','messaging.destination.name':'user-events','error.type':''},
    now64(9) - 60, now64(9),
    200, 2.0, [50,60,40,30,15,5,0,0,0,0,0], [0.005,0.01,0.025,0.05,0.075,0.1,0.25,0.5,0.75,1.0],
    0, 0.001, 0.08, 1
),
-- Simulated: notification-service publish errors
(
    {'service.name':'notification-service','k8s.namespace.name':'production','k8s.deployment.name':'notification-service','k8s.node.name':'node-1'},
    '', 'obi', '1.0', {}, 0, '',
    'notification-service', 'messaging.publish.duration', 'Duration of message publish', 's',
    {'messaging.system':'kafka','messaging.destination.name':'user-events','error.type':'broker_unavailable'},
    now64(9) - 60, now64(9),
    5, 5.0, [0,0,0,0,0,0,0,0,0,2,3], [0.005,0.01,0.025,0.05,0.075,0.1,0.25,0.5,0.75,1.0],
    0, 0.7, 1.2, 1
),
-- Simulated: email-worker consuming from Kafka
(
    {'service.name':'email-worker','k8s.namespace.name':'production','k8s.deployment.name':'email-worker','k8s.node.name':'node-2'},
    '', 'obi', '1.0', {}, 0, '',
    'email-worker', 'messaging.process.duration', 'Duration of message processing', 's',
    {'messaging.system':'kafka','messaging.destination.name':'user-events','error.type':''},
    now64(9) - 60, now64(9),
    180, 18.0, [10,20,30,40,35,25,15,3,2,0,0], [0.005,0.01,0.025,0.05,0.075,0.1,0.25,0.5,0.75,1.0],
    0, 0.002, 0.6, 1
),
-- Simulated: email-worker RabbitMQ queue
(
    {'service.name':'email-worker','k8s.namespace.name':'production','k8s.deployment.name':'email-worker','k8s.node.name':'node-2'},
    '', 'obi', '1.0', {}, 0, '',
    'email-worker', 'messaging.process.duration', 'Duration of message processing', 's',
    {'messaging.system':'rabbitmq','messaging.destination.name':'email-queue','error.type':''},
    now64(9) - 60, now64(9),
    90, 4.5, [20,25,20,15,5,3,2,0,0,0,0], [0.005,0.01,0.025,0.05,0.075,0.1,0.25,0.5,0.75,1.0],
    0, 0.001, 0.2, 1
)"
```

### 5.3 Verify Silver Tables Populated

The Materialized Views fire synchronously on INSERT, so data should appear immediately.

**Check silver_db_1m:**

```bash
kubectl exec $CH_POD -n $NAMESPACE --context $CONTEXT -- \
  clickhouse-client --user kvisor --password kvisor -d otel -q "
    SELECT
      service_name, db_system, db_operation, error_type,
      total_count, total_sum, min_value, max_value
    FROM silver_db_1m
    ORDER BY service_name, db_system, db_operation
    FORMAT PrettyCompact"
```

Expected output:
```
┌─service_name─────┬─db_system──┬─db_operation─┬─error_type─┬─total_count─┬─total_sum─┬─min_value─┬─max_value─┐
│ orders-api       │ postgresql │ INSERT       │            │          45 │      2.25 │     0.002 │      0.09 │
│ orders-api       │ postgresql │ SELECT       │            │         150 │       4.5 │     0.001 │      0.22 │
│ orders-api       │ postgresql │ SELECT       │ timeout    │           3 │         3 │       0.8 │       1.5 │
│ payments-service │ redis      │ GET          │            │         500 │       0.5 │    0.0001 │      0.04 │
└──────────────────┴────────────┴──────────────┴────────────┴─────────────┴───────────┴───────────┴───────────┘
```

**Check silver_messaging_1m:**

```bash
kubectl exec $CH_POD -n $NAMESPACE --context $CONTEXT -- \
  clickhouse-client --user kvisor --password kvisor -d otel -q "
    SELECT
      service_name, metric_name, messaging_system, messaging_destination,
      error_type, total_count, total_sum, min_value, max_value
    FROM silver_messaging_1m
    ORDER BY service_name, messaging_system, messaging_destination
    FORMAT PrettyCompact"
```

Expected output:
```
┌─service_name─────────┬─metric_name────────────────┬─messaging_system─┬─messaging_destination─┬─error_type─────────┬─total_count─┬─...─┐
│ email-worker         │ messaging.process.duration │ kafka            │ user-events           │                    │         180 │     │
│ email-worker         │ messaging.process.duration │ rabbitmq         │ email-queue           │                    │          90 │     │
│ notification-service │ messaging.publish.duration │ kafka            │ user-events           │                    │         200 │     │
│ notification-service │ messaging.publish.duration │ kafka            │ user-events           │ broker_unavailable │           5 │     │
└──────────────────────┴────────────────────────────┴──────────────────┴───────────────────────┴────────────────────┴─────────────┴─────┘
```

### 5.4 Verify All Silver Tables Summary

```bash
kubectl exec $CH_POD -n $NAMESPACE --context $CONTEXT -- \
  clickhouse-client --user kvisor --password kvisor -d otel -q "
    SELECT 'silver_http_1m' as tbl, count() as rows FROM silver_http_1m
    UNION ALL SELECT 'silver_grpc_1m', count() FROM silver_grpc_1m
    UNION ALL SELECT 'silver_gauge_1m', count() FROM silver_gauge_1m
    UNION ALL SELECT 'silver_db_1m', count() FROM silver_db_1m
    UNION ALL SELECT 'silver_messaging_1m', count() FROM silver_messaging_1m
    FORMAT PrettyCompact"
```

After simulation, `silver_db_1m` should have 4 rows and `silver_messaging_1m` should have
4 rows (in addition to any real data in the other tables).

### 5.5 Clean Up Synthetic Data

Remove the injected test data when done:

```bash
kubectl exec $CH_POD -n $NAMESPACE --context $CONTEXT -- \
  clickhouse-client --user kvisor --password kvisor -d otel -q "
    ALTER TABLE otel_metrics_histogram DELETE
    WHERE ServiceName IN ('orders-api','payments-service','notification-service','email-worker')
      AND ScopeName = 'obi' AND ScopeVersion = '1.0'"

kubectl exec $CH_POD -n $NAMESPACE --context $CONTEXT -- \
  clickhouse-client --user kvisor --password kvisor -d otel -q "
    ALTER TABLE silver_db_1m DELETE
    WHERE service_name IN ('orders-api','payments-service')"

kubectl exec $CH_POD -n $NAMESPACE --context $CONTEXT -- \
  clickhouse-client --user kvisor --password kvisor -d otel -q "
    ALTER TABLE silver_messaging_1m DELETE
    WHERE service_name IN ('notification-service','email-worker')"
```

> Note: `ALTER TABLE DELETE` is async in ClickHouse (creates a mutation). Rows disappear
> after the next merge. Run `OPTIMIZE TABLE <name> FINAL` to force immediate cleanup.

### 5.6 Adding a New Migration

To add a new metric type (e.g., a new silver table), create a new SQL file following the
goose convention:

```bash
# In cmd/clickhouse-migrate/migrations/otel/
cp 003_silver_db_messaging_gauge.sql 004_silver_custom.sql
```

Edit `004_silver_custom.sql`:
```sql
-- +goose Up
CREATE TABLE IF NOT EXISTS otel.silver_custom_1m ( ... )
ENGINE = AggregatingMergeTree ...;

CREATE MATERIALIZED VIEW IF NOT EXISTS otel.mv_bronze_to_silver_custom
TO otel.silver_custom_1m AS
SELECT ...
FROM otel.otel_metrics_histogram
WHERE MetricName = 'custom.metric.name'
GROUP BY ...;

-- +goose Down
DROP VIEW IF EXISTS otel.mv_bronze_to_silver_custom;
DROP TABLE IF EXISTS otel.silver_custom_1m;
```

Then rebuild the migration image and redeploy:
```bash
# Build
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/clickhouse-migrate-amd64 ./cmd/clickhouse-migrate
docker build --platform linux/amd64 -t eu.gcr.io/engineering-test-353509/kvisor-clickhouse-migrate:latest \
  --build-arg TARGETARCH=amd64 . -f Dockerfile.clickhouse-migrate
docker push eu.gcr.io/engineering-test-353509/kvisor-clickhouse-migrate:latest

# Update tag in obi-values.yaml, then deploy (pass 2 only if CH is already running)
helm upgrade $RELEASE ./charts/kvisor -n $NAMESPACE \
  --kube-context $CONTEXT --timeout 5m \
  -f charts/kvisor/obi-values.yaml \
  --set castai.apiKey=2a4dd76049e759eb4903e468666748f08f47157d5dbb5d65d78992d10e349963 \
  --set castai.clusterID=1e59b18a-f20e-4d7a-ba61-aff2636552a1 \
  --set castai.grpcAddr=kvisor.dev-master.cast.ai:443 \
  --set agent.extraArgs.netflow-enabled=true \
  --set controller.extraArgs.image-scan-enabled=true \
  --set controller.extraArgs.kube-bench-cloud-provider=gke \
  --set controller.extraArgs.kube-bench-enabled=true \
  --set controller.extraArgs.kube-linter-enabled=true
```

The migration Job will run `goose up`, detect that migrations 001-003 are already applied,
and only apply the new `004_silver_custom.sql`.

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
kubectl logs chi-castai-kvisor-clickhouse-otel-0-0-0 \
  -n $NAMESPACE --context $CONTEXT --previous
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

### Migration Job `Database X does not exist`

This is handled automatically by the v2 migration image which runs
`CREATE DATABASE IF NOT EXISTS` before connecting. If using an older image, create the
database manually:

```bash
kubectl exec chi-castai-kvisor-clickhouse-otel-0-0-0 \
  -n $NAMESPACE --context $CONTEXT -- \
  clickhouse-client -q "CREATE DATABASE IF NOT EXISTS kvisor"
```

### No data in ClickHouse after 5 minutes

1. Check OBI is instrumenting processes: `kubectl logs $POD -n $NAMESPACE --context $CONTEXT -c obi | grep instrumenting`
2. Check collector has no errors: `kubectl logs $POD -n $NAMESPACE --context $CONTEXT -c otel-collector | grep -i error`
3. Verify ClickHouse is accepting connections: `kubectl logs $CH_POD -n $NAMESPACE --context $CONTEXT | grep "Ready for connections"`
4. Check ClickHouse service is reachable from within the cluster:
   ```bash
   kubectl run ch-test --rm -it --image=busybox --restart=Never \
     -n $NAMESPACE --context $CONTEXT -- \
     wget -qO- http://castai-kvisor-clickhouse.castai-agent.svc.cluster.local:8123/ping
   ```
   Should return `Ok.`
