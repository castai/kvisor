package sustainability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/castai/kvisor/pkg/logging"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScraper_ScrapesAndExposesMetrics(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	// Setup mock Kepler server with realistic response
	keplerResponse := `# HELP kepler_container_joules_total Total joules consumed by the container
# TYPE kepler_container_joules_total counter
kepler_container_joules_total{container_id="123abc",container_namespace="production",pod_name="api-server-1",container_name="api"} 12345.6
kepler_container_joules_total{container_id="456def",container_namespace="production",pod_name="api-server-1",container_name="sidecar"} 1000.5
kepler_container_joules_total{container_id="789ghi",container_namespace="default",pod_name="test-pod",container_name="main"} 500.0
`

	mockKeplerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(keplerResponse))
	}))
	defer mockKeplerServer.Close()

	// Create logger following kvisor patterns
	log := logging.New(&logging.Config{
		Level: logging.MustParseLevel("debug"),
	})

	// Create test configuration
	cfg := &Config{
		Enabled:        true,
		KeplerEndpoint: mockKeplerServer.URL,
		ScrapeInterval: 100 * time.Millisecond, // Fast for testing
		NodeName:       "test-node-1",
	}

	// Create test Prometheus registry
	registry := prometheus.NewRegistry()

	// Create scraper instance
	scraper := NewScraper(log, cfg, registry)

	// Create context with timeout for test
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Start scraper
	err := scraper.Start(ctx)
	require.NoError(t, err)
	defer scraper.Stop()

	// Wait for at least one scrape cycle
	time.Sleep(200 * time.Millisecond)

	// Verify metrics are exposed in registry
	metrics, err := registry.Gather()
	require.NoError(t, err)

	// Find our sustainability metric
	var found bool
	var metricFamily *dto.MetricFamily
	for _, mf := range metrics {
		if mf.GetName() == "kvisor_sustainability_container_joules_total" {
			found = true
			metricFamily = mf
			break
		}
	}

	require.True(t, found, "kvisor_sustainability_container_joules_total metric not found")
	require.NotNil(t, metricFamily)

	// Verify we have the expected metrics
	containerMetrics := metricFamily.GetMetric()
	assert.Len(t, containerMetrics, 3, "Expected 3 container metrics")

	// Verify specific metric values and labels
	expectedMetrics := map[string]struct {
		namespace     string
		podName       string
		containerName string
		value         float64
	}{
		"production:api-server-1:api": {
			namespace:     "production",
			podName:       "api-server-1",
			containerName: "api",
			value:         12345.6,
		},
		"production:api-server-1:sidecar": {
			namespace:     "production",
			podName:       "api-server-1",
			containerName: "sidecar",
			value:         1000.5,
		},
		"default:test-pod:main": {
			namespace:     "default",
			podName:       "test-pod",
			containerName: "main",
			value:         500.0,
		},
	}

	foundMetrics := make(map[string]bool)
	for _, metric := range containerMetrics {
		labels := metric.GetLabel()

		// Extract label values
		var nodeName, namespace, podName, containerName string
		for _, label := range labels {
			switch label.GetName() {
			case "node_name":
				nodeName = label.GetValue()
			case "namespace":
				namespace = label.GetValue()
			case "pod_name":
				podName = label.GetValue()
			case "container_name":
				containerName = label.GetValue()
			}
		}

		// Verify node name is set correctly
		assert.Equal(t, "test-node-1", nodeName)

		// Create key for lookup
		key := namespace + ":" + podName + ":" + containerName
		expected, exists := expectedMetrics[key]
		require.True(t, exists, "Unexpected metric key: %s", key)

		// Verify metric value
		value := metric.GetGauge().GetValue()
		assert.Equal(t, expected.value, value, "Incorrect value for metric %s", key)

		foundMetrics[key] = true
	}

	// Ensure all expected metrics were found
	assert.Len(t, foundMetrics, len(expectedMetrics), "Not all expected metrics were found")
}

func TestScraper_HandlesMissingKeplerMetric(t *testing.T) {
	// Mock server that doesn't return the kepler metric
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`# HELP some_other_metric Some other metric
# TYPE some_other_metric counter
some_other_metric{label="value"} 123
`))
	}))
	defer mockServer.Close()

	log := logging.New(&logging.Config{
		Level: logging.MustParseLevel("debug"),
	})

	cfg := &Config{
		Enabled:        true,
		KeplerEndpoint: mockServer.URL,
		ScrapeInterval: 100 * time.Millisecond,
		NodeName:       "test-node",
	}

	registry := prometheus.NewRegistry()
	scraper := NewScraper(log, cfg, registry)

	// Perform single scrape
	ctx := context.Background()
	scraper.scrapeKepler(ctx)

	// Verify no sustainability metrics are created
	metricCount := testutil.CollectAndCount(scraper.containerEnergyJoules)
	assert.Equal(t, 0, metricCount, "No metrics should be created when Kepler metric is missing")
}

func TestScraper_HandlesKeplerServerError(t *testing.T) {
	// Mock server that returns error
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
	}))
	defer mockServer.Close()

	log := logging.New(&logging.Config{
		Level: logging.MustParseLevel("debug"),
	})

	cfg := &Config{
		Enabled:        true,
		KeplerEndpoint: mockServer.URL,
		ScrapeInterval: 100 * time.Millisecond,
		NodeName:       "test-node",
	}

	registry := prometheus.NewRegistry()
	scraper := NewScraper(log, cfg, registry)

	// Perform single scrape
	ctx := context.Background()
	scraper.scrapeKepler(ctx)

	// Verify error metric is incremented
	errorCount := testutil.ToFloat64(scraper.scrapeErrors)
	assert.Equal(t, 1.0, errorCount, "Error counter should be incremented on server error")
}

func TestScraper_DisabledConfiguration(t *testing.T) {
	log := logging.New(&logging.Config{
		Level: logging.MustParseLevel("info"),
	})

	cfg := &Config{
		Enabled:        false, // Disabled
		KeplerEndpoint: "http://localhost:8888/metrics",
		ScrapeInterval: DefaultScrapeInterval,
		NodeName:       "test-node",
	}

	registry := prometheus.NewRegistry()
	scraper := NewScraper(log, cfg, registry)

	ctx := context.Background()
	err := scraper.Start(ctx)
	require.NoError(t, err)

	// Should return immediately without starting goroutines
	scraper.Stop()

	// No metrics should be registered
	metrics, err := registry.Gather()
	require.NoError(t, err)

	// The metrics should be registered but have no values
	sustainabilityMetrics := 0
	for _, mf := range metrics {
		if mf.GetName() == "kvisor_sustainability_container_joules_total" ||
			mf.GetName() == "kvisor_sustainability_scrape_duration_seconds" ||
			mf.GetName() == "kvisor_sustainability_scrape_errors_total" ||
			mf.GetName() == "kvisor_sustainability_last_scrape_timestamp_seconds" {
			sustainabilityMetrics++
		}
	}

	assert.GreaterOrEqual(t, sustainabilityMetrics, 1, "At least one sustainability metric should be registered even when disabled")
}

func TestScraper_MetricLabelsValidation(t *testing.T) {
	// Mock response with missing required labels
	keplerResponse := `# HELP kepler_container_joules_total Total joules consumed by the container
# TYPE kepler_container_joules_total counter
kepler_container_joules_total{container_id="123",missing_namespace="test"} 100.0
kepler_container_joules_total{container_namespace="prod",missing_pod="test"} 200.0
kepler_container_joules_total{container_namespace="prod",pod_name="test",missing_container="main"} 300.0
`

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(keplerResponse))
	}))
	defer mockServer.Close()

	log := logging.New(&logging.Config{
		Level: logging.MustParseLevel("debug"),
	})

	cfg := &Config{
		Enabled:        true,
		KeplerEndpoint: mockServer.URL,
		ScrapeInterval: 100 * time.Millisecond,
		NodeName:       "test-node",
	}

	registry := prometheus.NewRegistry()
	scraper := NewScraper(log, cfg, registry)

	// Perform single scrape
	ctx := context.Background()
	scraper.scrapeKepler(ctx)

	// Verify no metrics are created due to missing required labels
	metricCount := testutil.CollectAndCount(scraper.containerEnergyJoules)
	assert.Equal(t, 0, metricCount, "No metrics should be created when required labels are missing")
}
