# OBI Reliability Metrics

OpenTelemetry eBPF Instrumentation (OBI) sidecar for automatic application-level
golden signal metrics — zero-code, zero-SDK, works on any Go/generic binary.

## Architecture

```
┌─────────────────────── DaemonSet (per node) ───────────────────────┐
│                                                                     │
│  kvisor          obi (eBPF)          otel-collector                 │
│  ───────         ──────────          ──────────────                 │
│  agent           uprobe attach       OTLP HTTP :4318 (receiver)     │
│                  to processes         ↓                              │
│                  on open ports       filter/golden-signals           │
│                       │              transform/cardinality           │
│                       │              batch (1024, 10s)               │
│                       └──OTLP──→     memory_limiter (100 MiB)       │
│                                      ↓                              │
│                                      prometheus exporter :9400      │
│                                      internal telemetry  :8888      │
│                                      health check        :13133     │
└─────────────────────────────────────────────────────────────────────┘
         │ :9400                              │ :8888
         ▼                                    ▼
   PodMonitor (otel-prom)              PodMonitor (otel-metrics)
         │                                    │
         └──────────── Prometheus ◄───────────┘
```

### Golden signal metrics kept

| Metric                           | Signal  | Source          |
|----------------------------------|---------|-----------------|
| `http.server.request.duration`   | Latency | HTTP server     |
| `rpc.server.duration`            | Latency | gRPC server     |
| `sql.client.duration`            | Latency | database/sql    |
| `redis.client.duration`          | Latency | go-redis        |
| `messaging.publish.duration`     | Latency | Kafka producer  |
| `messaging.process.duration`     | Latency | Kafka consumer  |

Everything else OBI emits is dropped by `filter/golden-signals`.

### Cardinality control

High-cardinality attributes stripped before Prometheus export:
`url.full`, `url.path`, `server.address`, `server.port`, `client.address`,
`client.port`, `network.peer.address`, `network.peer.port`, `user_agent.original`.

Retained for dashboards/SLOs: `http.request.method`, `http.response.status_code`,
`service.name`, `rpc.method`, `rpc.service`, `rpc.grpc.status_code`,
`db.system`, `messaging.system`, `messaging.destination.name`.

## Values files

| File                          | Cluster         | Notes                                  |
|-------------------------------|-----------------|----------------------------------------|
| `obi-values.yaml`            | kvisor-obi-test | Docker Hub images, `podMonitorLabels: release: kube-prometheus-stack` |
| `obi-values-dev-master.yaml` | dev-master      | Mirrored images (BinAuthz), no podMonitorLabels |

### Image mirroring (Binary Authorization)

Dev-master enforces `always_deny` Binary Authorization. Docker Hub images are blocked.
Images mirrored to `us-docker.pkg.dev/castai-hub/library/` using `crane`:

```shell
crane copy otel/ebpf-instrument:v0.4.1 \
  us-docker.pkg.dev/castai-hub/library/otel-ebpf-instrument:v0.4.1 --platform linux/amd64

crane copy otel/opentelemetry-collector-contrib:0.145.0 \
  us-docker.pkg.dev/castai-hub/library/otel-collector-contrib:0.145.0 --platform linux/amd64
```

Re-run these when upgrading OBI or collector versions.

## Deploy

### Test cluster (kvisor-obi-test)

```shell
helm upgrade castai-kvisor charts/kvisor -n castai-agent \
  --kube-context gke_engineering-test-353509_europe-west3_kvisor-obi-test \
  --reuse-values --history-max 0 \
  -f charts/kvisor/obi-values.yaml
```

### Dev-master

```shell
helm upgrade castai-kvisor charts/kvisor -n castai-agent \
  --kube-context dev-master \
  --reuse-values --history-max 0 \
  -f charts/kvisor/obi-values-dev-master.yaml
```

### After any deploy — force rollout

ConfigMap changes do not trigger DaemonSet restart (only `secret.yaml` is checksummed):

```shell
kubectl --context <CONTEXT> -n castai-agent rollout restart daemonset castai-kvisor-agent
```

## Verify

```shell
# Pods running 3/3 containers
kubectl --context <CONTEXT> -n castai-agent get pods \
  -l app.kubernetes.io/name=castai-kvisor-agent \
  -o custom-columns='NAME:.metadata.name,READY:.status.containerStatuses[*].ready,CONTAINERS:.spec.containers[*].name'

# OBI instrumenting processes
kubectl --context <CONTEXT> -n castai-agent logs \
  -l app.kubernetes.io/name=castai-kvisor-agent -c obi --tail=20

# OTel Collector healthy
kubectl --context <CONTEXT> -n castai-agent logs \
  -l app.kubernetes.io/name=castai-kvisor-agent -c otel-collector --tail=10

# PodMonitor exists
kubectl --context <CONTEXT> -n castai-agent get podmonitor castai-kvisor-agent-obi

# Prometheus scraping metrics (from Prometheus pod)
kubectl --context <CONTEXT> -n monitoring exec -it prometheus-kube-prometheus-stack-prometheus-0 -- \
  wget -qO- 'http://localhost:9090/api/v1/query?query=http_server_request_duration_seconds_count' | head -c 500
```

## Gotchas

- **CAP_SYS_ADMIN required** on GKE COS kernel for uprobe attachment (PERFMON alone is insufficient).
- **`--reuse-values` carries forward everything** — including `--set` overrides from previous upgrades. Use `--set 'key=null'` to clear.
- **ConfigMap changes need manual rollout** — `rollout restart daemonset` after deploy.
- **Binary Authorization** — dev-master (and likely production) blocks Docker Hub images. Mirror to an approved registry first.
- **PodMonitor labels vary by cluster** — check `kubectl get prometheus -A -o jsonpath='{.items[*].spec.podMonitorSelector}'` to see if the target Prometheus requires specific labels.
- **nil-safety in templates** — use `dig` for optional nested values (e.g. `dig "reliabilityMetrics" "enabled" false .Values.agent`).
- **Scratch containers** — all 3 containers are minimal/scratch, no shell or debugging tools.
- **OBI v0.4.1 support matrix**: HTTP server, gRPC server, HTTP client, Kafka (segmentio/kafka-go). Does NOT support: `database/sql` client or `go-redis` client metrics yet.

## Tests

```shell
helm unittest charts/kvisor -f tests/obi-sidecar/test.yaml
# 26 tests covering: sidecar injection, collector config, PodMonitor, RBAC, security contexts
```

## Future: push-based pipeline (no Prometheus dependency)

Current architecture requires Prometheus in the customer cluster. For GA, the plan is
to add a push exporter (ClickHouse or OTLP remote) so metrics flow directly to the
CAST AI backend:

```
Per-node DaemonSet (current):
  OBI → otel-collector → push app metrics to backend

Cluster-wide Deployment (new, single replica):
  k8s_cluster receiver  ─┐
  kubeletstats receiver  ─┤→ otel-collector → push infra metrics to backend
  k8sobjects receiver    ─┘
```

The `k8s_cluster` receiver (already in collector-contrib) replaces kube-state-metrics
dependency. Must run as single replica, not per-node — cannot go in the DaemonSet.
