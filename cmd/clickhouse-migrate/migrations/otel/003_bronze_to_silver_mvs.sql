-- +goose Up
-- =============================================================================
-- BRONZE -> SILVER MVs -- Incremental materialized views (in-cluster only)
-- =============================================================================
-- These MVs are only deployed on in-cluster ClickHouse. On mothership,
-- Silver tables are populated by the gRPC ingestion pipeline from the
-- reliability-metrics-ch-exporter sidecar.

-- Bronze histograms -> Silver HTTP
CREATE MATERIALIZED VIEW IF NOT EXISTS metrics.reliability_mv_bronze_to_silver_http
TO metrics.reliability_metrics_http
AS
SELECT
    toStartOfMinute(TimeUnix)                                           AS minute,
    ServiceName                                                         AS service_name,
    MetricName                                                          AS metric_name,
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
    count()                                                             AS sample_count,
    now64(3)                                                            AS timestamp,
    cityHash64(ServiceName,
               if(ResourceAttributes['k8s.namespace.name'] != '',
                  ResourceAttributes['k8s.namespace.name'],
                  ResourceAttributes['service.namespace']),
               ResourceAttributes['k8s.deployment.name'],
               Attributes['http.request.method'],
               Attributes['http.response.status_code'],
               toString(toStartOfMinute(TimeUnix)))                    AS pk
FROM metrics.otel_metrics_histogram
WHERE MetricName IN ('http.server.request.duration', 'http.client.request.duration')
GROUP BY minute, service_name, metric_name, k8s_namespace, k8s_deployment,
         k8s_node, error_type, http_method, http_status_code;

-- Bronze histograms -> Silver gRPC
CREATE MATERIALIZED VIEW IF NOT EXISTS metrics.reliability_mv_bronze_to_silver_grpc
TO metrics.reliability_metrics_grpc
AS
SELECT
    toStartOfMinute(TimeUnix)                                           AS minute,
    ServiceName                                                         AS service_name,
    MetricName                                                          AS metric_name,
    if(ResourceAttributes['k8s.namespace.name'] != '',
       ResourceAttributes['k8s.namespace.name'],
       ResourceAttributes['service.namespace'])                         AS k8s_namespace,
    ResourceAttributes['k8s.deployment.name']                           AS k8s_deployment,
    ResourceAttributes['k8s.node.name']                                 AS k8s_node,
    Attributes['error.type']                                            AS error_type,
    Attributes['rpc.method']                                            AS rpc_method,
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
    count()                                                             AS sample_count,
    now64(3)                                                            AS timestamp,
    cityHash64(ServiceName,
               if(ResourceAttributes['k8s.namespace.name'] != '',
                  ResourceAttributes['k8s.namespace.name'],
                  ResourceAttributes['service.namespace']),
               ResourceAttributes['k8s.deployment.name'],
               Attributes['rpc.method'],
               if(Attributes['rpc.service'] != '',
                  Attributes['rpc.service'],
                  if(position(Attributes['rpc.method'], '/') > 0,
                     extractAll(Attributes['rpc.method'], '^/([^/]+)/')[1],
                     '')),
               Attributes['rpc.grpc.status_code'],
               toString(toStartOfMinute(TimeUnix)))                    AS pk
FROM metrics.otel_metrics_histogram
WHERE MetricName IN ('rpc.server.duration', 'rpc.client.duration')
GROUP BY minute, service_name, metric_name, k8s_namespace, k8s_deployment,
         k8s_node, error_type, rpc_method, rpc_service, rpc_grpc_status_code;

-- Bronze histograms -> Silver DB
CREATE MATERIALIZED VIEW IF NOT EXISTS metrics.reliability_mv_bronze_to_silver_db
TO metrics.reliability_metrics_db
AS
SELECT
    toStartOfMinute(TimeUnix)                                           AS minute,
    ServiceName                                                         AS service_name,
    MetricName                                                          AS metric_name,
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
    count()                                                             AS sample_count,
    now64(3)                                                            AS timestamp,
    cityHash64(ServiceName,
               if(ResourceAttributes['k8s.namespace.name'] != '',
                  ResourceAttributes['k8s.namespace.name'],
                  ResourceAttributes['service.namespace']),
               ResourceAttributes['k8s.deployment.name'],
               Attributes['db.system.name'],
               Attributes['db.operation.name'],
               toString(toStartOfMinute(TimeUnix)))                    AS pk
FROM metrics.otel_metrics_histogram
WHERE MetricName = 'db.client.operation.duration'
GROUP BY minute, service_name, metric_name, k8s_namespace, k8s_deployment,
         k8s_node, error_type, db_system, db_operation;

-- Bronze histograms -> Silver Messaging
CREATE MATERIALIZED VIEW IF NOT EXISTS metrics.reliability_mv_bronze_to_silver_messaging
TO metrics.reliability_metrics_messaging
AS
SELECT
    toStartOfMinute(TimeUnix)                                           AS minute,
    ServiceName                                                         AS service_name,
    MetricName                                                          AS metric_name,
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
    count()                                                             AS sample_count,
    now64(3)                                                            AS timestamp,
    cityHash64(ServiceName,
               if(ResourceAttributes['k8s.namespace.name'] != '',
                  ResourceAttributes['k8s.namespace.name'],
                  ResourceAttributes['service.namespace']),
               ResourceAttributes['k8s.deployment.name'],
               Attributes['messaging.system'],
               Attributes['messaging.destination.name'],
               toString(toStartOfMinute(TimeUnix)))                    AS pk
FROM metrics.otel_metrics_histogram
WHERE MetricName IN ('messaging.publish.duration', 'messaging.process.duration')
GROUP BY minute, service_name, metric_name, k8s_namespace, k8s_deployment,
         k8s_node, error_type, messaging_system, messaging_destination;

-- Bronze gauges -> Silver Gauge
CREATE MATERIALIZED VIEW IF NOT EXISTS metrics.reliability_mv_bronze_to_silver_gauge
TO metrics.reliability_metrics_gauge
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
    count()                                                             AS sample_count,
    now64(3)                                                            AS timestamp,
    cityHash64(ResourceAttributes['k8s.namespace.name'],
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
                   'unknown'),
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
                   ''),
               MetricName,
               ResourceAttributes['k8s.node.name'],
               toString(toStartOfMinute(TimeUnix)))                    AS pk
FROM metrics.otel_metrics_gauge
GROUP BY minute, metric_name, k8s_namespace, resource_type, resource_name, k8s_node;

-- +goose Down
DROP VIEW IF EXISTS metrics.reliability_mv_bronze_to_silver_gauge;
DROP VIEW IF EXISTS metrics.reliability_mv_bronze_to_silver_messaging;
DROP VIEW IF EXISTS metrics.reliability_mv_bronze_to_silver_db;
DROP VIEW IF EXISTS metrics.reliability_mv_bronze_to_silver_grpc;
DROP VIEW IF EXISTS metrics.reliability_mv_bronze_to_silver_http;
