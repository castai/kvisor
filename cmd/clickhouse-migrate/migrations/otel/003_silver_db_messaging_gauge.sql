-- +goose Up
-- =============================================================================
-- SILVER LAYER — Database, Messaging, and Gauge 1-minute aggregates
-- =============================================================================

-- Silver: Database — Per-service, per-minute DB client histogram aggregates
CREATE TABLE IF NOT EXISTS otel.silver_db_1m
(
    minute                  DateTime CODEC(Delta, ZSTD(1)),
    service_name            LowCardinality(String) CODEC(ZSTD(1)),
    metric_name             LowCardinality(String) CODEC(ZSTD(1)),
    k8s_namespace           LowCardinality(String) CODEC(ZSTD(1)),
    k8s_deployment          LowCardinality(String) CODEC(ZSTD(1)),
    k8s_node                LowCardinality(String) CODEC(ZSTD(1)),
    error_type              LowCardinality(String) CODEC(ZSTD(1)),
    db_system               LowCardinality(String) CODEC(ZSTD(1)),
    db_operation            LowCardinality(String) CODEC(ZSTD(1)),
    total_count             SimpleAggregateFunction(sum, UInt64),
    total_sum               SimpleAggregateFunction(sum, Float64),
    min_value               SimpleAggregateFunction(min, Float64),
    max_value               SimpleAggregateFunction(max, Float64),
    bucket_counts           AggregateFunction(sumForEach, Array(UInt64)),
    explicit_bounds         SimpleAggregateFunction(anyLast, Array(Float64)),
    sample_count            SimpleAggregateFunction(sum, UInt64)
)
ENGINE = AggregatingMergeTree
PARTITION BY toDate(minute)
ORDER BY (service_name, k8s_namespace, k8s_deployment, db_system, db_operation, minute)
TTL minute + INTERVAL 7 DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

-- Incremental MV: Bronze histograms → Silver DB
CREATE MATERIALIZED VIEW IF NOT EXISTS otel.mv_bronze_to_silver_db
TO otel.silver_db_1m
AS
SELECT
    toStartOfMinute(TimeUnix)                                           AS minute,
    ServiceName                                                         AS service_name,
    MetricName                                                          AS metric_name,
    -- Fallback: k8s.namespace.name -> service.namespace
    if(ResourceAttributes['k8s.namespace.name'] != '',
       ResourceAttributes['k8s.namespace.name'],
       ResourceAttributes['service.namespace'])                         AS k8s_namespace,
    ResourceAttributes['k8s.deployment.name']                           AS k8s_deployment,
    ResourceAttributes['k8s.node.name']                                 AS k8s_node,
    Attributes['error.type']                                            AS error_type,
    Attributes['db.system.name']                                        AS db_system,
    Attributes['db.operation.name']                                     AS db_operation,
    sum(Count)                                                          AS total_count,
    sum(Sum)                                                            AS total_sum,
    min(Min)                                                            AS min_value,
    max(Max)                                                            AS max_value,
    sumForEachState(BucketCounts)                                       AS bucket_counts,
    anyLast(ExplicitBounds)                                             AS explicit_bounds,
    count()                                                             AS sample_count
FROM otel.otel_metrics_histogram
WHERE MetricName = 'db.client.operation.duration'
GROUP BY minute, service_name, metric_name, k8s_namespace, k8s_deployment,
         k8s_node, error_type, db_system, db_operation;

-- Silver: Messaging — Per-service, per-minute messaging histogram aggregates
CREATE TABLE IF NOT EXISTS otel.silver_messaging_1m
(
    minute                  DateTime CODEC(Delta, ZSTD(1)),
    service_name            LowCardinality(String) CODEC(ZSTD(1)),
    metric_name             LowCardinality(String) CODEC(ZSTD(1)),
    k8s_namespace           LowCardinality(String) CODEC(ZSTD(1)),
    k8s_deployment          LowCardinality(String) CODEC(ZSTD(1)),
    k8s_node                LowCardinality(String) CODEC(ZSTD(1)),
    error_type              LowCardinality(String) CODEC(ZSTD(1)),
    messaging_system        LowCardinality(String) CODEC(ZSTD(1)),
    messaging_destination   LowCardinality(String) CODEC(ZSTD(1)),
    total_count             SimpleAggregateFunction(sum, UInt64),
    total_sum               SimpleAggregateFunction(sum, Float64),
    min_value               SimpleAggregateFunction(min, Float64),
    max_value               SimpleAggregateFunction(max, Float64),
    bucket_counts           AggregateFunction(sumForEach, Array(UInt64)),
    explicit_bounds         SimpleAggregateFunction(anyLast, Array(Float64)),
    sample_count            SimpleAggregateFunction(sum, UInt64)
)
ENGINE = AggregatingMergeTree
PARTITION BY toDate(minute)
ORDER BY (service_name, k8s_namespace, k8s_deployment, messaging_system, messaging_destination, minute)
TTL minute + INTERVAL 7 DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

-- Incremental MV: Bronze histograms → Silver Messaging
CREATE MATERIALIZED VIEW IF NOT EXISTS otel.mv_bronze_to_silver_messaging
TO otel.silver_messaging_1m
AS
SELECT
    toStartOfMinute(TimeUnix)                                           AS minute,
    ServiceName                                                         AS service_name,
    MetricName                                                          AS metric_name,
    -- Fallback: k8s.namespace.name -> service.namespace
    if(ResourceAttributes['k8s.namespace.name'] != '',
       ResourceAttributes['k8s.namespace.name'],
       ResourceAttributes['service.namespace'])                         AS k8s_namespace,
    ResourceAttributes['k8s.deployment.name']                           AS k8s_deployment,
    ResourceAttributes['k8s.node.name']                                 AS k8s_node,
    Attributes['error.type']                                            AS error_type,
    Attributes['messaging.system']                                      AS messaging_system,
    Attributes['messaging.destination.name']                            AS messaging_destination,
    sum(Count)                                                          AS total_count,
    sum(Sum)                                                            AS total_sum,
    min(Min)                                                            AS min_value,
    max(Max)                                                            AS max_value,
    sumForEachState(BucketCounts)                                       AS bucket_counts,
    anyLast(ExplicitBounds)                                             AS explicit_bounds,
    count()                                                             AS sample_count
FROM otel.otel_metrics_histogram
WHERE MetricName IN ('messaging.publish.duration', 'messaging.process.duration')
GROUP BY minute, service_name, metric_name, k8s_namespace, k8s_deployment,
         k8s_node, error_type, messaging_system, messaging_destination;

-- Silver: Gauge — Per-resource, per-minute gauge aggregates (KSM metrics)
CREATE TABLE IF NOT EXISTS otel.silver_gauge_1m
(
    minute                  DateTime CODEC(Delta, ZSTD(1)),
    metric_name             LowCardinality(String) CODEC(ZSTD(1)),
    k8s_namespace           LowCardinality(String) CODEC(ZSTD(1)),
    resource_type           LowCardinality(String) CODEC(ZSTD(1)),
    resource_name           LowCardinality(String) CODEC(ZSTD(1)),
    k8s_node                LowCardinality(String) CODEC(ZSTD(1)),
    last_value              SimpleAggregateFunction(anyLast, Float64),
    min_value               SimpleAggregateFunction(min, Float64),
    max_value               SimpleAggregateFunction(max, Float64),
    sample_count            SimpleAggregateFunction(sum, UInt64)
)
ENGINE = AggregatingMergeTree
PARTITION BY toDate(minute)
ORDER BY (k8s_namespace, resource_type, resource_name, metric_name, k8s_node, minute)
TTL minute + INTERVAL 7 DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

-- Incremental MV: Bronze gauges → Silver 1-minute aggregates
CREATE MATERIALIZED VIEW IF NOT EXISTS otel.mv_bronze_to_silver_gauge
TO otel.silver_gauge_1m
AS
SELECT
    toStartOfMinute(TimeUnix)                                           AS minute,
    MetricName                                                          AS metric_name,
    ResourceAttributes['k8s.namespace.name']                            AS k8s_namespace,
    multiIf(
        MetricName LIKE 'k8s.deployment.%',    'deployment',
        MetricName LIKE 'k8s.statefulset.%',   'statefulset',
        MetricName LIKE 'k8s.daemonset.%',     'daemonset',
        MetricName LIKE 'k8s.replicaset.%',    'replicaset',
        MetricName LIKE 'k8s.pod.%' OR MetricName LIKE 'k8s.container.%', 'pod',
        MetricName LIKE 'k8s.node.%',          'node',
        MetricName LIKE 'k8s.hpa.%',           'hpa',
        MetricName LIKE 'k8s.job.%',           'job',
        MetricName LIKE 'k8s.cronjob.%',       'cronjob',
        'unknown'
    )                                                                   AS resource_type,
    coalesce(
        nullIf(ResourceAttributes['k8s.deployment.name'], ''),
        nullIf(ResourceAttributes['k8s.statefulset.name'], ''),
        nullIf(ResourceAttributes['k8s.daemonset.name'], ''),
        nullIf(ResourceAttributes['k8s.replicaset.name'], ''),
        nullIf(ResourceAttributes['k8s.cronjob.name'], ''),
        nullIf(ResourceAttributes['k8s.job.name'], ''),
        nullIf(ResourceAttributes['k8s.hpa.name'], ''),
        nullIf(ResourceAttributes['k8s.pod.name'], ''),
        nullIf(ResourceAttributes['k8s.node.name'], ''),
        ''
    )                                                                   AS resource_name,
    ResourceAttributes['k8s.node.name']                                 AS k8s_node,
    anyLast(Value)                                                      AS last_value,
    min(Value)                                                          AS min_value,
    max(Value)                                                          AS max_value,
    count()                                                             AS sample_count
FROM otel.otel_metrics_gauge
GROUP BY minute, metric_name, k8s_namespace, resource_type, resource_name, k8s_node;

-- +goose Down
DROP VIEW IF EXISTS otel.mv_bronze_to_silver_gauge;
DROP TABLE IF EXISTS otel.silver_gauge_1m;
DROP VIEW IF EXISTS otel.mv_bronze_to_silver_messaging;
DROP TABLE IF EXISTS otel.silver_messaging_1m;
DROP VIEW IF EXISTS otel.mv_bronze_to_silver_db;
DROP TABLE IF EXISTS otel.silver_db_1m;
