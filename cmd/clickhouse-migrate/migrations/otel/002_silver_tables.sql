-- +goose Up
-- =============================================================================
-- SILVER LAYER -- 1-minute aggregated golden signals (in-cluster)
-- =============================================================================
-- Deployed on in-cluster ClickHouse (single node, no replication).
-- Bronze->Silver MVs populate these (see 003_bronze_to_silver_mvs.sql).
-- The CH exporter sidecar reads from these and sends to mothership.

-- Silver: HTTP
CREATE TABLE IF NOT EXISTS metrics.reliability_metrics_http
(
    org_id                  UUID,
    cluster_id              UUID,
    minute                  DateTime CODEC(Delta, ZSTD(1)),
    metric_name             LowCardinality(String) CODEC(ZSTD(1)),
    workload_name           LowCardinality(String) CODEC(ZSTD(1)),
    workload_namespace      LowCardinality(String) CODEC(ZSTD(1)),
    workload_kind           LowCardinality(String) CODEC(ZSTD(1)),
    k8s_node                LowCardinality(String) CODEC(ZSTD(1)),
    error_type              LowCardinality(String) CODEC(ZSTD(1)),
    http_method             LowCardinality(String) CODEC(ZSTD(1)),
    http_status_code        LowCardinality(String) CODEC(ZSTD(1)),
    total_count             SimpleAggregateFunction(sum, UInt64),
    total_sum               SimpleAggregateFunction(sum, Float64),
    min_value               SimpleAggregateFunction(min, Float64),
    max_value               SimpleAggregateFunction(max, Float64),
    bucket_counts           AggregateFunction(sumForEach, Array(UInt64)),
    explicit_bounds         SimpleAggregateFunction(anyLast, Array(Float64)),
    sample_count            SimpleAggregateFunction(sum, UInt64),
    timestamp               SimpleAggregateFunction(max, DateTime) CODEC(Delta, ZSTD(1)),
    pk                      UInt64 CODEC(ZSTD(1))
)
ENGINE = AggregatingMergeTree
PARTITION BY toDate(minute)
ORDER BY (workload_name, workload_namespace, workload_kind, http_method, http_status_code, minute)
TTL minute + INTERVAL 7 DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

-- Silver: gRPC
CREATE TABLE IF NOT EXISTS metrics.reliability_metrics_grpc
(
    org_id                  UUID,
    cluster_id              UUID,
    minute                  DateTime CODEC(Delta, ZSTD(1)),
    metric_name             LowCardinality(String) CODEC(ZSTD(1)),
    workload_name           LowCardinality(String) CODEC(ZSTD(1)),
    workload_namespace      LowCardinality(String) CODEC(ZSTD(1)),
    workload_kind           LowCardinality(String) CODEC(ZSTD(1)),
    k8s_node                LowCardinality(String) CODEC(ZSTD(1)),
    error_type              LowCardinality(String) CODEC(ZSTD(1)),
    rpc_method              LowCardinality(String) CODEC(ZSTD(1)),
    rpc_service             LowCardinality(String) CODEC(ZSTD(1)),
    rpc_grpc_status_code    LowCardinality(String) CODEC(ZSTD(1)),
    total_count             SimpleAggregateFunction(sum, UInt64),
    total_sum               SimpleAggregateFunction(sum, Float64),
    min_value               SimpleAggregateFunction(min, Float64),
    max_value               SimpleAggregateFunction(max, Float64),
    bucket_counts           AggregateFunction(sumForEach, Array(UInt64)),
    explicit_bounds         SimpleAggregateFunction(anyLast, Array(Float64)),
    sample_count            SimpleAggregateFunction(sum, UInt64),
    timestamp               SimpleAggregateFunction(max, DateTime) CODEC(Delta, ZSTD(1)),
    pk                      UInt64 CODEC(ZSTD(1))
)
ENGINE = AggregatingMergeTree
PARTITION BY toDate(minute)
ORDER BY (workload_name, workload_namespace, workload_kind, rpc_method, rpc_service, rpc_grpc_status_code, minute)
TTL minute + INTERVAL 7 DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

-- Silver: Database
CREATE TABLE IF NOT EXISTS metrics.reliability_metrics_db
(
    org_id                  UUID,
    cluster_id              UUID,
    minute                  DateTime CODEC(Delta, ZSTD(1)),
    metric_name             LowCardinality(String) CODEC(ZSTD(1)),
    workload_name           LowCardinality(String) CODEC(ZSTD(1)),
    workload_namespace      LowCardinality(String) CODEC(ZSTD(1)),
    workload_kind           LowCardinality(String) CODEC(ZSTD(1)),
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
    sample_count            SimpleAggregateFunction(sum, UInt64),
    timestamp               SimpleAggregateFunction(max, DateTime) CODEC(Delta, ZSTD(1)),
    pk                      UInt64 CODEC(ZSTD(1))
)
ENGINE = AggregatingMergeTree
PARTITION BY toDate(minute)
ORDER BY (workload_name, workload_namespace, workload_kind, db_system, db_operation, minute)
TTL minute + INTERVAL 7 DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

-- Silver: Messaging
CREATE TABLE IF NOT EXISTS metrics.reliability_metrics_messaging
(
    org_id                  UUID,
    cluster_id              UUID,
    minute                  DateTime CODEC(Delta, ZSTD(1)),
    metric_name             LowCardinality(String) CODEC(ZSTD(1)),
    workload_name           LowCardinality(String) CODEC(ZSTD(1)),
    workload_namespace      LowCardinality(String) CODEC(ZSTD(1)),
    workload_kind           LowCardinality(String) CODEC(ZSTD(1)),
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
    sample_count            SimpleAggregateFunction(sum, UInt64),
    timestamp               SimpleAggregateFunction(max, DateTime) CODEC(Delta, ZSTD(1)),
    pk                      UInt64 CODEC(ZSTD(1))
)
ENGINE = AggregatingMergeTree
PARTITION BY toDate(minute)
ORDER BY (workload_name, workload_namespace, workload_kind, messaging_system, messaging_destination, minute)
TTL minute + INTERVAL 7 DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

-- Silver: Gauge
CREATE TABLE IF NOT EXISTS metrics.reliability_metrics_gauge
(
    org_id                  UUID,
    cluster_id              UUID,
    minute                  DateTime CODEC(Delta, ZSTD(1)),
    metric_name             LowCardinality(String) CODEC(ZSTD(1)),
    workload_name           LowCardinality(String) CODEC(ZSTD(1)),
    workload_namespace      LowCardinality(String) CODEC(ZSTD(1)),
    workload_kind           LowCardinality(String) CODEC(ZSTD(1)),
    k8s_node                LowCardinality(String) CODEC(ZSTD(1)),
    last_value              SimpleAggregateFunction(anyLast, Float64),
    min_value               SimpleAggregateFunction(min, Float64),
    max_value               SimpleAggregateFunction(max, Float64),
    sample_count            SimpleAggregateFunction(sum, UInt64),
    timestamp               SimpleAggregateFunction(max, DateTime) CODEC(Delta, ZSTD(1)),
    pk                      UInt64 CODEC(ZSTD(1))
)
ENGINE = AggregatingMergeTree
PARTITION BY toDate(minute)
ORDER BY (workload_namespace, workload_kind, workload_name, metric_name, k8s_node, minute)
TTL minute + INTERVAL 7 DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

-- +goose Down
DROP TABLE IF EXISTS metrics.reliability_metrics_gauge;
DROP TABLE IF EXISTS metrics.reliability_metrics_messaging;
DROP TABLE IF EXISTS metrics.reliability_metrics_db;
DROP TABLE IF EXISTS metrics.reliability_metrics_grpc;
DROP TABLE IF EXISTS metrics.reliability_metrics_http;
