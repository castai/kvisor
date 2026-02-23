-- +goose Up
-- =============================================================================
-- SILVER LAYER — HTTP and gRPC 1-minute aggregated golden signals
-- =============================================================================

-- Silver: HTTP — Per-service, per-minute HTTP histogram aggregates
CREATE TABLE IF NOT EXISTS otel.silver_http_1m
(
    minute                  DateTime CODEC(Delta, ZSTD(1)),
    service_name            LowCardinality(String) CODEC(ZSTD(1)),
    metric_name             LowCardinality(String) CODEC(ZSTD(1)),
    k8s_namespace           LowCardinality(String) CODEC(ZSTD(1)),
    k8s_deployment          LowCardinality(String) CODEC(ZSTD(1)),
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
    sample_count            SimpleAggregateFunction(sum, UInt64)
)
ENGINE = AggregatingMergeTree
PARTITION BY toDate(minute)
ORDER BY (service_name, k8s_namespace, k8s_deployment, http_method, http_status_code, minute)
TTL minute + INTERVAL 7 DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

-- Incremental MV: Bronze histograms → Silver HTTP
CREATE MATERIALIZED VIEW IF NOT EXISTS otel.mv_bronze_to_silver_http
TO otel.silver_http_1m
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
    Attributes['http.request.method']                                   AS http_method,
    Attributes['http.response.status_code']                             AS http_status_code,
    sum(Count)                                                          AS total_count,
    sum(Sum)                                                            AS total_sum,
    min(Min)                                                            AS min_value,
    max(Max)                                                            AS max_value,
    sumForEachState(BucketCounts)                                       AS bucket_counts,
    anyLast(ExplicitBounds)                                             AS explicit_bounds,
    count()                                                             AS sample_count
FROM otel.otel_metrics_histogram
WHERE MetricName IN ('http.server.request.duration', 'http.client.request.duration')
GROUP BY minute, service_name, metric_name, k8s_namespace, k8s_deployment,
         k8s_node, error_type, http_method, http_status_code;

-- Silver: gRPC — Per-service, per-minute gRPC histogram aggregates
CREATE TABLE IF NOT EXISTS otel.silver_grpc_1m
(
    minute                  DateTime CODEC(Delta, ZSTD(1)),
    service_name            LowCardinality(String) CODEC(ZSTD(1)),
    metric_name             LowCardinality(String) CODEC(ZSTD(1)),
    k8s_namespace           LowCardinality(String) CODEC(ZSTD(1)),
    k8s_deployment          LowCardinality(String) CODEC(ZSTD(1)),
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
    sample_count            SimpleAggregateFunction(sum, UInt64)
)
ENGINE = AggregatingMergeTree
PARTITION BY toDate(minute)
ORDER BY (service_name, k8s_namespace, k8s_deployment, rpc_method, rpc_service, rpc_grpc_status_code, minute)
TTL minute + INTERVAL 7 DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

-- Incremental MV: Bronze histograms → Silver gRPC
CREATE MATERIALIZED VIEW IF NOT EXISTS otel.mv_bronze_to_silver_grpc
TO otel.silver_grpc_1m
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
    Attributes['rpc.method']                                            AS rpc_method,
    -- Fallback: rpc.service -> parse from rpc.method (/package.Service/Method)
    if(Attributes['rpc.service'] != '',
       Attributes['rpc.service'],
       if(position(Attributes['rpc.method'], '/') > 0,
          extractAll(Attributes['rpc.method'], '^/([^/]+)/')[1],
          ''
       )
    )                                                                   AS rpc_service,
    Attributes['rpc.grpc.status_code']                                  AS rpc_grpc_status_code,
    sum(Count)                                                          AS total_count,
    sum(Sum)                                                            AS total_sum,
    min(Min)                                                            AS min_value,
    max(Max)                                                            AS max_value,
    sumForEachState(BucketCounts)                                       AS bucket_counts,
    anyLast(ExplicitBounds)                                             AS explicit_bounds,
    count()                                                             AS sample_count
FROM otel.otel_metrics_histogram
WHERE MetricName IN ('rpc.server.duration', 'rpc.client.duration')
GROUP BY minute, service_name, metric_name, k8s_namespace, k8s_deployment,
         k8s_node, error_type, rpc_method, rpc_service, rpc_grpc_status_code;

-- +goose Down
DROP VIEW IF EXISTS otel.mv_bronze_to_silver_grpc;
DROP TABLE IF EXISTS otel.silver_grpc_1m;
DROP VIEW IF EXISTS otel.mv_bronze_to_silver_http;
DROP TABLE IF EXISTS otel.silver_http_1m;
