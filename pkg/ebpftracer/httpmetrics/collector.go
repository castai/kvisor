package httpmetrics

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/castai/kvisor/pkg/containers"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/logging"
	httputil "github.com/castai/kvisor/pkg/net/http"
	"github.com/castai/kvisor/pkg/net/packet"
	"github.com/elastic/go-freelru"
)

const (
	// DefaultPendingRequestsCacheSize is the max number of pending HTTP requests to track
	DefaultPendingRequestsCacheSize = 4096

	// DefaultPendingRequestTTL is how long to wait for a response before expiring a request
	DefaultPendingRequestTTL = 30 * time.Second

	// DefaultFlushInterval is how often to log/flush aggregated metrics
	DefaultFlushInterval = 30 * time.Second

	// DefaultMaxPathTemplates is the max number of unique path templates to track
	DefaultMaxPathTemplates = 1000
)

// ConnectionKey uniquely identifies a TCP connection for request-response correlation
type ConnectionKey struct {
	CgroupID uint64
	SrcAddr  netip.Addr
	SrcPort  uint16
	DstAddr  netip.Addr
	DstPort  uint16
}

// PendingRequest tracks an HTTP request awaiting a response
type PendingRequest struct {
	Method    string
	Path      string
	Host      string
	Timestamp time.Time
	Container *containers.Container
}

// MetricsKey is the aggregation key for HTTP metrics
type MetricsKey struct {
	Namespace    string
	PodName      string
	Method       string
	PathTemplate string
}

// MetricsBucket holds aggregated metrics for a single endpoint
type MetricsBucket struct {
	RequestCount uint64
	Status2xx    uint64
	Status3xx    uint64
	Status4xx    uint64
	Status5xx    uint64

	// Latency tracking
	LatencySum   float64 // sum of latencies in milliseconds
	LatencyCount uint64

	// Histogram buckets (ms): <10, <25, <50, <100, <250, <500, <1000, >1000
	LatencyBuckets [8]uint64
}

// Config holds configuration for the HTTP metrics collector
type Config struct {
	PendingRequestsCacheSize uint32
	PendingRequestTTL        time.Duration
	FlushInterval            time.Duration
	MaxPathTemplates         int
}

// Collector collects and aggregates HTTP metrics
type Collector struct {
	log             *logging.Logger
	config          Config
	mu              sync.RWMutex
	pendingRequests *freelru.SyncedLRU[ConnectionKey, *PendingRequest]
	metrics         map[MetricsKey]*MetricsBucket
	pathTracker     *httputil.PathTemplateTracker
	flushTicker     *time.Ticker
	stopCh          chan struct{}
}

// NewCollector creates a new HTTP metrics collector
func NewCollector(log *logging.Logger, cfg Config) (*Collector, error) {
	if cfg.PendingRequestsCacheSize == 0 {
		cfg.PendingRequestsCacheSize = DefaultPendingRequestsCacheSize
	}
	if cfg.PendingRequestTTL == 0 {
		cfg.PendingRequestTTL = DefaultPendingRequestTTL
	}
	if cfg.FlushInterval == 0 {
		cfg.FlushInterval = DefaultFlushInterval
	}
	if cfg.MaxPathTemplates == 0 {
		cfg.MaxPathTemplates = DefaultMaxPathTemplates
	}

	cache, err := freelru.NewSynced[ConnectionKey, *PendingRequest](cfg.PendingRequestsCacheSize, hashConnectionKey)
	if err != nil {
		return nil, fmt.Errorf("creating pending requests cache: %w", err)
	}
	cache.SetLifetime(cfg.PendingRequestTTL)

	c := &Collector{
		log:             log,
		config:          cfg,
		pendingRequests: cache,
		metrics:         make(map[MetricsKey]*MetricsBucket),
		pathTracker:     httputil.NewPathTemplateTracker(cfg.MaxPathTemplates),
		stopCh:          make(chan struct{}),
	}

	return c, nil
}

// Start begins the background flush loop
func (c *Collector) Start() {
	c.flushTicker = time.NewTicker(c.config.FlushInterval)
	go c.flushLoop()
}

// Stop stops the collector
func (c *Collector) Stop() {
	close(c.stopCh)
	if c.flushTicker != nil {
		c.flushTicker.Stop()
	}
}

func (c *Collector) flushLoop() {
	for {
		select {
		case <-c.stopCh:
			return
		case <-c.flushTicker.C:
			c.FlushAndLog()
		}
	}
}

// ProcessHTTPEvent processes an HTTP packet event
func (c *Collector) ProcessHTTPEvent(event *types.Event, payload []byte) {
	c.log.Infof("ProcessHTTPEvent called with payload len=%d, cgroup=%d", len(payload), event.Context.CgroupID)
	if len(payload) == 0 {
		return
	}

	// Extract packet details (includes IP/port info)
	details, err := packet.ExtractPacketDetails(payload)
	if err != nil {
		c.log.Debugf("failed to extract packet details: %v", err)
		return
	}

	// Parse the HTTP message
	httpMsg, err := packet.ParseHTTP(details.Payload)
	if err != nil {
		c.log.Debugf("failed to parse HTTP: %v", err)
		return
	}

	// Build connection key
	connKey := ConnectionKey{
		CgroupID: event.Context.CgroupID,
		SrcAddr:  details.Src.Addr(),
		SrcPort:  details.Src.Port(),
		DstAddr:  details.Dst.Addr(),
		DstPort:  details.Dst.Port(),
	}

	switch msg := httpMsg.(type) {
	case *packet.HTTPRequest:
		c.handleRequest(connKey, msg, event)
	case *packet.HTTPResponse:
		c.handleResponse(connKey, msg, event)
	}
}

func (c *Collector) handleRequest(key ConnectionKey, req *packet.HTTPRequest, event *types.Event) {
	pending := &PendingRequest{
		Method:    req.Method,
		Path:      req.Path,
		Host:      req.Host,
		Timestamp: time.Unix(0, int64(event.Context.Ts)), //nolint:gosec // timestamp overflow is not a concern
		Container: event.Container,
	}
	c.pendingRequests.Add(key, pending)

	c.log.Debugf("HTTP request: %s %s (host=%s, cgroup=%d)", req.Method, req.Path, req.Host, key.CgroupID)
}

func (c *Collector) handleResponse(key ConnectionKey, resp *packet.HTTPResponse, event *types.Event) {
	// For response, we need to look up the request with reversed src/dst
	reverseKey := ConnectionKey{
		CgroupID: key.CgroupID,
		SrcAddr:  key.DstAddr,
		SrcPort:  key.DstPort,
		DstAddr:  key.SrcAddr,
		DstPort:  key.SrcPort,
	}

	pending, found := c.pendingRequests.Get(reverseKey)
	if !found {
		c.log.Debugf("HTTP response without matching request: %d %s", resp.StatusCode, resp.Status)
		return
	}
	c.pendingRequests.Remove(reverseKey)

	// Calculate latency
	responseTime := time.Unix(0, int64(event.Context.Ts)) //nolint:gosec // timestamp overflow is not a concern
	latency := responseTime.Sub(pending.Timestamp)

	// Normalize path
	normalizedPath := c.pathTracker.Track(pending.Path)

	// Build metrics key
	metricsKey := MetricsKey{
		Method:       pending.Method,
		PathTemplate: normalizedPath,
	}
	if pending.Container != nil {
		metricsKey.Namespace = pending.Container.PodNamespace
		metricsKey.PodName = pending.Container.PodName
	}

	// Update metrics
	c.updateMetrics(metricsKey, resp.StatusCode, latency)

	c.log.Debugf("HTTP response: %d %s (method=%s, path=%s, latency=%v)",
		resp.StatusCode, resp.Status, pending.Method, normalizedPath, latency)
}

func (c *Collector) updateMetrics(key MetricsKey, statusCode int, latency time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	bucket, exists := c.metrics[key]
	if !exists {
		bucket = &MetricsBucket{}
		c.metrics[key] = bucket
	}

	bucket.RequestCount++

	// Update status class
	switch {
	case statusCode >= 200 && statusCode < 300:
		bucket.Status2xx++
	case statusCode >= 300 && statusCode < 400:
		bucket.Status3xx++
	case statusCode >= 400 && statusCode < 500:
		bucket.Status4xx++
	case statusCode >= 500:
		bucket.Status5xx++
	}

	// Update latency
	latencyMs := float64(latency.Milliseconds())
	bucket.LatencySum += latencyMs
	bucket.LatencyCount++

	// Update histogram buckets
	switch {
	case latencyMs < 10:
		bucket.LatencyBuckets[0]++
	case latencyMs < 25:
		bucket.LatencyBuckets[1]++
	case latencyMs < 50:
		bucket.LatencyBuckets[2]++
	case latencyMs < 100:
		bucket.LatencyBuckets[3]++
	case latencyMs < 250:
		bucket.LatencyBuckets[4]++
	case latencyMs < 500:
		bucket.LatencyBuckets[5]++
	case latencyMs < 1000:
		bucket.LatencyBuckets[6]++
	default:
		bucket.LatencyBuckets[7]++
	}
}

// FlushAndLog logs the current metrics and resets them
func (c *Collector) FlushAndLog() {
	c.mu.Lock()
	metrics := c.metrics
	c.metrics = make(map[MetricsKey]*MetricsBucket)
	pathCount := c.pathTracker.Count()
	c.pathTracker.Reset()
	c.mu.Unlock()

	if len(metrics) == 0 {
		return
	}

	c.log.Infof("HTTP metrics flush: %d endpoints, %d unique paths", len(metrics), pathCount)

	for key, bucket := range metrics {
		avgLatency := float64(0)
		if bucket.LatencyCount > 0 {
			avgLatency = bucket.LatencySum / float64(bucket.LatencyCount)
		}

		c.log.Infof("http_metrics namespace=%s pod=%s method=%s path=%s requests=%d 2xx=%d 3xx=%d 4xx=%d 5xx=%d avg_latency_ms=%.2f",
			key.Namespace,
			key.PodName,
			key.Method,
			key.PathTemplate,
			bucket.RequestCount,
			bucket.Status2xx,
			bucket.Status3xx,
			bucket.Status4xx,
			bucket.Status5xx,
			avgLatency,
		)
	}
}

// GetMetrics returns the current metrics (for testing or external access)
func (c *Collector) GetMetrics() map[MetricsKey]*MetricsBucket {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Return a copy
	result := make(map[MetricsKey]*MetricsBucket, len(c.metrics))
	for k, v := range c.metrics {
		bucketCopy := *v
		result[k] = &bucketCopy
	}
	return result
}

// DumpToJSON returns the metrics as JSON (useful for file dump)
func (c *Collector) DumpToJSON() ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	type metricEntry struct {
		Namespace      string    `json:"namespace"`
		PodName        string    `json:"pod_name"`
		Method         string    `json:"method"`
		PathTemplate   string    `json:"path_template"`
		RequestCount   uint64    `json:"request_count"`
		Status2xx      uint64    `json:"status_2xx"`
		Status3xx      uint64    `json:"status_3xx"`
		Status4xx      uint64    `json:"status_4xx"`
		Status5xx      uint64    `json:"status_5xx"`
		AvgLatencyMs   float64   `json:"avg_latency_ms"`
		LatencyBuckets [8]uint64 `json:"latency_buckets_ms"`
	}

	entries := make([]metricEntry, 0, len(c.metrics))
	for key, bucket := range c.metrics {
		avgLatency := float64(0)
		if bucket.LatencyCount > 0 {
			avgLatency = bucket.LatencySum / float64(bucket.LatencyCount)
		}
		entries = append(entries, metricEntry{
			Namespace:      key.Namespace,
			PodName:        key.PodName,
			Method:         key.Method,
			PathTemplate:   key.PathTemplate,
			RequestCount:   bucket.RequestCount,
			Status2xx:      bucket.Status2xx,
			Status3xx:      bucket.Status3xx,
			Status4xx:      bucket.Status4xx,
			Status5xx:      bucket.Status5xx,
			AvgLatencyMs:   avgLatency,
			LatencyBuckets: bucket.LatencyBuckets,
		})
	}

	return json.MarshalIndent(entries, "", "  ")
}

// hashConnectionKey generates a hash for the ConnectionKey
func hashConnectionKey(key ConnectionKey) uint32 {
	// Simple hash combining cgroup and ports
	h := uint32(key.CgroupID) //nolint:gosec // hash truncation is intentional
	h ^= uint32(key.SrcPort) << 16
	h ^= uint32(key.DstPort)
	// Include some address bits
	if key.SrcAddr.Is4() {
		addr := key.SrcAddr.As4()
		h ^= uint32(addr[0])<<24 | uint32(addr[1])<<16 | uint32(addr[2])<<8 | uint32(addr[3])
	}
	return h
}
