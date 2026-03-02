# Kvisor Reliability Metrics Installation Guide

> **⚠️ ALPHA - NOT FOR PRODUCTION USE**
>
> This feature is currently in alpha and is not intended for production use. APIs, configurations, and functionality may change without notice.

This guide covers installing Kvisor with the reliability metrics stack, which provides automated observability for applications running in your Kubernetes cluster.

## Overview

The reliability metrics stack extends Kvisor with eBPF-based application instrumentation (OBI) and automatic golden signal metrics collection (latency, error rate, throughput) for HTTP, gRPC, database, and messaging protocols.

## Prerequisites

- Kubernetes cluster
- `helm` and `kubectl` installed and configured
- CAST AI account with API key and cluster onboarded to CAST AI

## Installation Options

### Option 1: Fresh Installation with Reliability Metrics

Install Kvisor with reliability metrics enabled from the start:

```bash
# Update chart dependencies
helm dependency update ./charts/kvisor

# Install with reliability metrics enabled
helm install castai-kvisor ./charts/kvisor \
  -n castai-agent --create-namespace \
  --set castai.apiKey=<your-api-key> \
  --set castai.clusterID=<your-cluster-id> \
  --set castai.grpcAddr=<grpc-endpoint> \
  --set reliabilityMetrics.enabled=true
```

### Option 2: Add Reliability Metrics to Existing Kvisor Installation

Upgrade an existing Kvisor installation to enable reliability metrics:

```bash
# Update chart dependencies
helm dependency update ./charts/kvisor

# Upgrade with reliability metrics enabled
helm upgrade castai-kvisor ./charts/kvisor \
  -n castai-agent \
  --set castai.apiKey=<your-api-key> \
  --set castai.clusterID=<your-cluster-id> \
  --set castai.grpcAddr=<grpc-endpoint> \
  --set reliabilityMetrics.enabled=true
```

**Important:** Do NOT use `--reuse-values` when enabling reliability metrics, as this will cause template errors due to new nested configuration values.

## Configuration

### Basic Configuration

The minimal configuration requires only enabling the feature:

```yaml
reliabilityMetrics:
  enabled: true
```

### Advanced Configuration

For production deployments, you may want to customize:

```yaml
reliabilityMetrics:
  enabled: true

  # ClickHouse operator settings
  clickhouse:
    operator:
      enabled: true

    # External ClickHouse (alternative to in-cluster)
    external:
      enabled: false
      # host: external-clickhouse.example.com
      # port: 9000
```

### Using a Values File

Create a values file (e.g., `reliability-values.yaml`):

```yaml
castai:
  apiKey: <your-api-key>
  clusterID: <your-cluster-id>
  grpcAddr: <grpc-endpoint>

reliabilityMetrics:
  enabled: true

agent:
  extraArgs:
    netflow-enabled: true

controller:
  extraArgs:
    image-scan-enabled: true
    kube-bench-enabled: true
    kube-linter-enabled: true
```

Then install or upgrade:

```bash
helm upgrade --install castai-kvisor ./charts/kvisor \
  -n castai-agent --create-namespace \
  -f reliability-values.yaml
```

## Verification

### 1. Check Pod Status

Verify all pods are running:

```bash
kubectl get pods -n castai-agent
```

Expected pods when reliability metrics are enabled:
- `castai-kvisor-agent-*` (3/3 Running) - includes kvisor, OBI, and OpenTelemetry collector
- `castai-kvisor-controller-*` (2/2 Running) - includes controller and OpenTelemetry collector
- `chi-castai-kvisor-clickhouse-*` (2/2 Running) - ClickHouse database and exporter
- `castai-kvisor-clickhouse-operator-*` (2/2 Running) - ClickHouse operator
- `castai-kvisor-clickhouse-migrate-*` (0/1 Completed) - database migration job

### 2. Verify OBI Instrumentation

Check that OBI is instrumenting your applications:

```bash
# Get any agent pod
POD=$(kubectl get pods -n castai-agent \
  -l app.kubernetes.io/name=castai-kvisor-agent -o name | head -1)

# Check instrumentation logs
kubectl logs $POD -n castai-agent -c obi | grep 'instrumenting'
```

You should see log lines showing processes being instrumented:
```
level=INFO msg="instrumenting process" cmd=... pid=... type=go
```

### 3. Verify OpenTelemetry Collectors

Check that the collectors are running:

```bash
# Agent collector
kubectl logs $POD -n castai-agent -c otel-collector --tail=5
```

Should show:
```
Everything is ready. Begin running and processing data.
```

### 4. Verify Data Collection

After a few minutes, verify that metrics are being collected:

```bash
# Get ClickHouse pod
CH_POD=$(kubectl get pods -n castai-agent \
  -l clickhouse.altinity.com/chi=castai-kvisor-clickhouse -o name | head -1 | cut -d'/' -f2)

# Check tables exist
kubectl exec $CH_POD -n castai-agent -c clickhouse -- \
  clickhouse-client -d metrics -q "SHOW TABLES"

# Check for data (wait 2-3 minutes after installation)
kubectl exec $CH_POD -n castai-agent -c clickhouse -- \
  clickhouse-client -d metrics -q "
    SELECT count() as total_metrics
    FROM otel_metrics_histogram"
```

If you see a non-zero count, metrics are being collected successfully.

## What Gets Instrumented

The reliability metrics stack automatically discovers and instruments:

- **HTTP services** - Request duration, error rates, throughput by endpoint and status code
- **gRPC services** - Request duration, error rates, throughput by method
- **Database clients** - Query duration and error rates (MySQL, PostgreSQL, etc.)
- **Messaging systems** - Message processing duration and error rates
- **Kubernetes resources** - Pod restarts, container states, resource metrics

No code changes or manual instrumentation required.

## Startup Timeline

After installation, components start in this sequence:

| Time | Component | Status |
|------|-----------|--------|
| 0-30s | OpenTelemetry collectors | Start collecting and buffering data |
| 30-120s | ClickHouse database | Starts up, schema migrations run |
| 60-180s | Full data flow | Collectors drain buffers, metrics flow to database |
| 180s+ | Export to CAST AI | Data begins exporting to CAST AI platform |

## Troubleshooting

### Pods Not Starting

Check pod status and events:
```bash
kubectl get pods -n castai-agent
kubectl describe pod <pod-name> -n castai-agent
```

### No Metrics Being Collected

1. Verify OBI is running and instrumenting processes (see Verification step 2)
2. Check OpenTelemetry collector logs for errors:
   ```bash
   kubectl logs $POD -n castai-agent -c otel-collector | grep -i error
   ```
3. Verify ClickHouse is ready:
   ```bash
   kubectl logs $CH_POD -n castai-agent -c clickhouse --tail=20
   ```

### Connection Errors During Startup

Transient connection errors during the first 2-3 minutes after installation are normal. The OpenTelemetry collectors automatically retry and buffer data while ClickHouse starts up. If errors persist beyond 5 minutes, check that ClickHouse is running properly.

### Migration Job Failed

Check migration logs:
```bash
kubectl logs -l app.kubernetes.io/component=migrate -n castai-agent
```

The migration job should show successful migration completion. If it failed, check ClickHouse connectivity and logs.

## Uninstalling

To disable reliability metrics while keeping Kvisor:

```bash
helm upgrade castai-kvisor ./charts/kvisor \
  -n castai-agent \
  --set reliabilityMetrics.enabled=false \
  --reuse-values
```

To completely uninstall Kvisor:

```bash
helm uninstall castai-kvisor -n castai-agent
```

Note: ClickHouse PersistentVolumeClaims are not automatically deleted. To remove them:

```bash
kubectl delete pvc -n castai-agent -l app.kubernetes.io/instance=castai-kvisor
```

## Next Steps

Once installed, reliability metrics will automatically flow to your CAST AI dashboard, where you can:

- View application golden signals (latency, error rate, throughput)
- Correlate application performance with infrastructure costs

For more information, visit the [CAST AI documentation](https://docs.cast.ai).
