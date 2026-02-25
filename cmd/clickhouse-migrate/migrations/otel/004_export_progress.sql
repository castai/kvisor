-- +goose Up
-- =============================================================================
-- EXPORT PROGRESS -- Cursor tracking for the reliability-metrics-ch-exporter
-- =============================================================================
-- The exporter polls silver tables using (timestamp, pk) as a cursor.
-- Each row here tells the exporter which table to export, what columns to
-- SELECT, and where it left off. The mothership_table_name maps to the
-- destination collection (distributed table) on mothership.

CREATE TABLE IF NOT EXISTS metrics.export_progress
(
    table_name            String,
    mothership_table_name String,
    columns               String,
    uploaded_at           DateTime64(3),
    last_exported_time    DateTime64(3),
    last_exported_pk      UInt64
)
ENGINE = ReplacingMergeTree()
ORDER BY (table_name, uploaded_at);

-- Seed rows -- one per silver table.
-- last_exported_time = epoch (export everything from the beginning).
-- mothership_table_name = _local table on mothership (direct insert).
-- NOTE: org_id/cluster_id are NOT exported; the metrics-ingestor adds them
--       server-side from the authenticated cluster identity.
-- NOTE: bucket_counts uses AggregateFunction(sumForEach, ...) so we finalize
--       it with sumForEachMerge() directly in the columns string.
--       explicit_bounds is SimpleAggregateFunction(anyLast, ...) which returns
--       plain Array(Float64) on SELECT — no -Merge combinator needed.
-- NOTE: timestamp is NOT exported; the ingestor sets it server-side (default behaviour).
INSERT INTO metrics.export_progress
    (table_name, mothership_table_name, columns, uploaded_at, last_exported_time, last_exported_pk)
VALUES
    ('reliability_metrics_http',
     'reliability_metrics_http_local',
     'minute, service_name, metric_name, k8s_namespace, k8s_deployment, k8s_node, error_type, http_method, http_status_code, total_count, total_sum, min_value, max_value, sumForEachMerge(bucket_counts) AS bucket_counts, explicit_bounds, sample_count',
     now64(3), toDateTime64('1970-01-01 00:00:00.000', 3), 0),

    ('reliability_metrics_grpc',
     'reliability_metrics_grpc_local',
     'minute, service_name, metric_name, k8s_namespace, k8s_deployment, k8s_node, error_type, rpc_method, rpc_service, rpc_grpc_status_code, total_count, total_sum, min_value, max_value, sumForEachMerge(bucket_counts) AS bucket_counts, explicit_bounds, sample_count',
     now64(3), toDateTime64('1970-01-01 00:00:00.000', 3), 0),

    ('reliability_metrics_db',
     'reliability_metrics_db_local',
     'minute, service_name, metric_name, k8s_namespace, k8s_deployment, k8s_node, error_type, db_system, db_operation, total_count, total_sum, min_value, max_value, sumForEachMerge(bucket_counts) AS bucket_counts, explicit_bounds, sample_count',
     now64(3), toDateTime64('1970-01-01 00:00:00.000', 3), 0),

    ('reliability_metrics_messaging',
     'reliability_metrics_messaging_local',
     'minute, service_name, metric_name, k8s_namespace, k8s_deployment, k8s_node, error_type, messaging_system, messaging_destination, total_count, total_sum, min_value, max_value, sumForEachMerge(bucket_counts) AS bucket_counts, explicit_bounds, sample_count',
     now64(3), toDateTime64('1970-01-01 00:00:00.000', 3), 0),

    ('reliability_metrics_gauge',
     'reliability_metrics_gauge_local',
     'minute, metric_name, k8s_namespace, resource_type, resource_name, k8s_node, last_value, min_value, max_value, sample_count',
     now64(3), toDateTime64('1970-01-01 00:00:00.000', 3), 0);

-- +goose Down
DROP TABLE IF EXISTS metrics.export_progress;
