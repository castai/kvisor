# HTTP Reliability Metrics Collection for Kvisor

## Overview

Add L7 HTTP metrics collection to Kvisor for CAST AI's WOOP and Cost Reporting services. This extends the existing eBPF-based monitoring to capture latency histograms, error rates, and request counts per workload+endpoint.

**Target metrics:**
- Latency: P50/P95/P99 histograms per endpoint
- Error rate: Count by status class (2xx/3xx/4xx/5xx)
- Traffic: Request count per interval

**Dimensions:** namespace, workload (name+kind), HTTP method, normalized path template

## Architecture Decision

**Recommendation: Native implementation** (not Beyla/OBI integration)

Rationale:
1. Follows existing Kvisor patterns (SOCKS5, SSH, DNS detection at [socks5_detected.go](pkg/ebpftracer/signature/socks5_detected.go))
2. Direct control over data model and aggregation
3. Simpler integration with existing gRPC export pipeline
4. Avoids Beyla's separate deployment model and uprobe complexity

### Tracee HTTP Events Reference

Kvisor's eBPF layer is based on [Aqua Tracee](https://github.com/aquasecurity/tracee). **Tracee already has HTTP event support** that can be used as reference:

- `net_packet_http_request` - captures HTTP request method, path, host, headers
- `net_packet_http_response` - captures HTTP response status code, headers

Sample event data exists in `tools/hack/events.txt` showing the expected format:
```json
// Request
{"method":"POST","protocol":"HTTP/1.1","host":"127.0.0.1:2021","uri_path":"/logs","headers":{...}}

// Response
{"status":"200 OK","status_code":200,"protocol":"HTTP/1.1","headers":{...}}
```

**However, Kvisor has not implemented these events yet** - the eBPF code at `pkg/ebpftracer/c/tracee.bpf.c` only has DNS, SOCKS5, and SSH detection (lines 2166-2300).

**Implementation options:**
1. **Port from Tracee** - Check upstream Tracee for HTTP detection code and adapt it
2. **Implement fresh** - Follow existing Kvisor L7 patterns (simpler, ensures consistency)

**Note:** Tracee's HTTP support is also HTTP/1.1 plaintext only. For HTTP/2, gRPC, and TLS decryption, Beyla/OBI integration would be required (future phases).

**Phased approach:**
- **Phase 1 (this plan):** Unencrypted HTTP/1.1 - captures majority of internal K8s traffic
- **Phase 2 (future):** TLS/HTTPS via uprobe hooks for external API calls
- **Phase 3 (future):** HTTP/2 and gRPC protocol support

**Why HTTP/1.1-only is sufficient for Phase 1:**
- Internal service-to-service calls in K8s are typically plaintext HTTP
- Service mesh (Istio/Linkerd) terminates mTLS at sidecar; app traffic is unencrypted
- Health checks, metrics endpoints, internal APIs use HTTP
- Covers ~70-90% of internal cluster traffic

**Protocol support comparison:**

| Feature | Native (this plan) | Tracee | Beyla/OBI |
|---------|-------------------|--------|-----------|
| HTTP/1.1 plaintext | ✅ Phase 1 | ✅ Has it | ✅ |
| HTTP/2 plaintext (H2C) | ❌ Complex | ❌ | ✅ |
| TLS/HTTPS decryption | ❌ Needs uprobes | ❌ | ✅ |
| gRPC | ❌ Needs H2 | ❌ | ✅ |
| Go runtime TLS | ❌ Complex | ❌ | ✅ |

---

## Implementation Plan

### 1. eBPF Layer - HTTP Detection

**Files to modify:**

| File | Changes |
|------|---------|
| [pkg/ebpftracer/c/headers/types.h](pkg/ebpftracer/c/headers/types.h) | Add `NET_PACKET_HTTP` constant |
| [pkg/ebpftracer/events/events.go](pkg/ebpftracer/events/events.go) | Add `NetPacketHTTPBase` event ID |
| [pkg/ebpftracer/c/tracee.bpf.c](pkg/ebpftracer/c/tracee.bpf.c) | Add HTTP detection functions and handler |

**eBPF changes in tracee.bpf.c:**

1. Add `net_l7_is_http_request()` - detect HTTP methods (GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS)
2. Add `net_l7_is_http_response()` - detect "HTTP/1." prefix
3. Add `CGROUP_SKB_HANDLE_FUNCTION(proto_tcp_http)` - capture first 256 bytes of payload
4. Wire into existing TCP handler (around line 2315) similar to SSH/SOCKS5

### 2. Userspace HTTP Parsing

**New files to create:**

| File | Purpose |
|------|---------|
| `pkg/net/packet/http.go` | Parse HTTP request line (method, path) and response status code |
| `pkg/net/packet/http_test.go` | Unit tests for parser |
| `pkg/net/http/normalizer.go` | Path normalization (/users/123 → /users/{id}) |
| `pkg/net/http/normalizer_test.go` | Normalizer tests |

**Normalization rules:**
- Remove query strings
- Replace UUIDs with `{uuid}`
- Replace numeric segments with `{id}`
- Replace hex hashes (32+ chars) with `{hash}`
- Cap unique templates at 1000 (overflow → `/{overflow}`)

### 3. Request-Response Correlation & Aggregation

**New file:** `pkg/ebpftracer/signature/http_metrics.go`

Key components:
- `ConnectionKey` - identifies TCP connection (cgroup + 5-tuple)
- `PendingRequest` - tracks request awaiting response (method, path, timestamp)
- `HTTPMetricsBucket` - aggregated metrics per workload+endpoint
- LRU cache (4096 entries, 30s TTL) for pending requests

**Aggregation logic:**
1. On HTTP request: store in pending cache with timestamp
2. On HTTP response: lookup pending request (reverse 5-tuple), calculate latency, update bucket
3. Bucket by: namespace + workload_name + workload_kind + method + normalized_path

**Latency histogram buckets (ms):** <10, <25, <50, <100, <250, <500, <1000, >1000

### 4. Proto Message Definitions

**File to modify:** [api/v1/runtime/common.proto](api/v1/runtime/common.proto)

```protobuf
message HTTPMetrics {
  uint64 timestamp = 1;
  string namespace = 2;
  string workload_name = 3;
  string workload_kind = 4;
  string node_name = 5;
  repeated HTTPMetricsBucket buckets = 6;
}

message HTTPMetricsBucket {
  string method = 1;
  string path_template = 2;
  uint64 request_count = 3;
  uint64 status_2xx = 4;
  uint64 status_3xx = 5;
  uint64 status_4xx = 6;
  uint64 status_5xx = 7;
  double latency_sum_ms = 8;
  uint64 latency_count = 9;
  repeated uint64 latency_histogram = 10;  // 8 buckets
}
```

**File to modify:** [api/v1/runtime/runtime_agent_api.proto](api/v1/runtime/runtime_agent_api.proto)

Add to `DataBatchItem` oneof:
```protobuf
HTTPMetrics http_metrics = 15;
```

### 5. Output (PoC Simplified)

**For the PoC, skip the full gRPC export pipeline.** Instead, output metrics via:

**Option A: Structured Logging (Recommended for PoC)**
- Log aggregated metrics every flush interval (30s) using existing logger
- Easy to verify with `kubectl logs` or local debugging
- Example output:
```
INFO http_metrics flush namespace=default workload=nginx method=GET path=/api/users requests=150 status_2xx=140 status_5xx=10 p50_ms=12 p99_ms=89
```

**Option B: File Dump**
- Write JSON/CSV to ephemeral storage (e.g., `/tmp/http-metrics.json`)
- Useful for offline analysis or importing to spreadsheet

**Option C: Prometheus Metrics (if already exposed)**
- Add counters/histograms to existing `/metrics` endpoint
- Can scrape locally with `curl localhost:6060/metrics`

**Minimal integration:**
- Add collector to pipeline controller
- Flush on ticker, log/dump instead of `sendDataBatch()`
- No proto changes needed for PoC

### 6. Configuration (PoC Minimal)

For the PoC, keep configuration simple - hardcode sensible defaults or use environment variables:

```go
// Hardcoded for PoC
const (
    HTTPMetricsFlushInterval = 30 * time.Second
    HTTPMetricsMaxPaths      = 1000
    HTTPMetricsLogOutput     = true  // vs file dump
)
```

Full CLI flag integration can be added later if the PoC proves successful.

### 7. Event Wiring

**Files to modify:**

| File | Changes |
|------|---------|
| [pkg/ebpftracer/types/types.go](pkg/ebpftracer/types/types.go) | Add `NetPacketHTTPBaseArgs` struct |
| [pkg/ebpftracer/decoder/decoder.go](pkg/ebpftracer/decoder/decoder.go) | Add case for HTTP event decoding |
| [pkg/ebpftracer/tracer_decode.go](pkg/ebpftracer/tracer_decode.go) | Route HTTP events to metrics collector |

---

## Memory Optimization

**Cardinality control (minimize memory, not data volume):**
- Cap unique path templates at configurable limit (default 1000)
- Use LRU eviction for pending request correlation cache
- Periodic flush resets aggregation buckets
- Overflow paths grouped under `/{overflow}` template

**Memory-efficient structures:**
- Use `freelru.SyncedLRU` for connection tracking (same as SOCKS5 pattern)
- Fixed-size latency histogram (8 buckets, not HDR histogram)
- String interning for repeated namespace/workload names

---

## Testing Strategy

### Unit Tests
- HTTP parser: valid/malformed requests and responses
- Path normalizer: UUID, numeric, hash replacement
- Metrics collector: correlation, latency calculation, cardinality limit

### Integration Tests
- Add test in `pkg/ebpftracer/tracer_playground_test.go` pattern
- Generate HTTP traffic, verify events captured
- Verify pipeline exports correct proto structure

### E2E Test
- New file: `e2e/http-metrics-generator.yaml`
- Deploy simple HTTP server + client in Kind cluster
- Validate metrics reach mock exporter

---

## Files Summary

### New Files (PoC - Reduced Scope)
1. `pkg/net/packet/http.go` - HTTP parser
2. `pkg/net/http/normalizer.go` - Path normalizer
3. `pkg/ebpftracer/signature/http_metrics.go` - Aggregation collector + logging output

Tests and E2E can be added after PoC validation.

### Modified Files (PoC - Reduced Scope)
1. `pkg/ebpftracer/c/headers/types.h` - Add NET_PACKET_HTTP constant
2. `pkg/ebpftracer/events/events.go` - Add NetPacketHTTPBase event ID
3. `pkg/ebpftracer/c/tracee.bpf.c` - HTTP detection + handler
4. `pkg/ebpftracer/types/types.go` - Add args struct
5. `pkg/ebpftracer/decoder/decoder.go` - Decode HTTP events
6. `pkg/ebpftracer/tracer_decode.go` - Route to collector
7. `cmd/agent/daemon/pipeline/controller.go` - Initialize collector + flush loop

**Skipped for PoC (not needed):**
- Proto changes (no gRPC export)
- Config/daemon flags (hardcode defaults)
- App initialization complexity

---

## Verification (PoC)

1. **eBPF detection:** Run `curl http://localhost:8080/test` in a pod, verify HTTP events appear in debug logs
2. **Request/Response correlation:** Verify latency is computed (response timestamp - request timestamp)
3. **Aggregation:** Check logged metrics show correct counts per endpoint after flush interval
4. **Status codes:** Generate 200s, 404s, 500s and verify they're bucketed correctly
5. **Path normalization:** Hit `/users/123` and `/users/456`, verify they aggregate under `/users/{id}`

**Simple test setup:**
```bash
# Deploy a simple HTTP server (nginx or httpbin)
kubectl run httpbin --image=kennethreitz/httpbin --port=80

# Generate traffic
kubectl exec -it <kvisor-pod> -- curl http://httpbin/get
kubectl exec -it <kvisor-pod> -- curl http://httpbin/status/500

# Check kvisor logs for HTTP metrics output
kubectl logs <kvisor-pod> | grep http_metrics
```

---

## Reference: Existing Kvisor Architecture

### Key Files for Context
- **eBPF main program:** `pkg/ebpftracer/c/tracee.bpf.c` - L7 detection at lines 2165-2466
- **SOCKS5 signature pattern:** `pkg/ebpftracer/signature/socks5_detected.go` - ~160 lines
- **Netflow pipeline pattern:** `cmd/agent/daemon/pipeline/netflow_pipeline.go` - aggregation & export
- **Proto definitions:** `api/v1/runtime/common.proto` - existing message types
- **Pipeline controller:** `cmd/agent/daemon/pipeline/controller.go` - orchestrates all pipelines
- **Sample HTTP event data:** `tools/hack/events.txt` - shows Tracee HTTP event format

### Existing L7 Protocol Detection
| Protocol | Event | Detection Method |
|----------|-------|------------------|
| DNS | `NetPacketDNSBase` | Port-based + full parse in eBPF |
| SOCKS5 | `NetPacketSOCKS5Base` | Port 1080 + version/method check |
| SSH | `NetPacketSSHBase` | Port 22 + "SSH-" signature |
| HTTP | Not implemented | Tracee has it, Kvisor doesn't yet |

### Tracee Upstream Reference
- **Tracee GitHub:** https://github.com/aquasecurity/tracee
- **HTTP events docs:** https://aquasecurity.github.io/tracee/v0.11/docs/tracing/network-events/
- Kvisor is based on Tracee's eBPF layer (see `tracee.bpf.c` filename and GPL-2.0 license)
- Tracee's HTTP detection code could potentially be ported back to Kvisor

### Export Pipeline Flow
```
eBPF Events → ringbuf → Decoder → Signature Engine → Pipeline → DataBatchWriter → gRPC
```
