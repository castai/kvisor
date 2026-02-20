package main_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	otelmetric "go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"

	"github.com/cilium/cilium/pkg/time"

	"github.com/castai/kvisor/cmd/agent/collector/app"
	"github.com/castai/kvisor/cmd/agent/collector/config"
)

// Test_CollectorIntegration tests the full OTel collector pipeline end-to-end:
//  1. The collector is started with ClickHouse enabled.
//  2. OTLP histogram metrics are sent over HTTP to the collector.
//  3. The metrics pass through filter / cumulativetodelta / batch processors.
//  4. The ClickHouse exporter writes them into otel_metrics_histogram.
//  5. The test queries ClickHouse and verifies the stored data.
//
// Requires Docker to be available. Skipped with -short.
func Test_CollectorIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	r := require.New(t)

	// 1. Start a ClickHouse container via testcontainers-go (pinned to v0.35.0 for docker v27 compatibility).
	chNativeAddr, chCleanup := startClickhouseDB(t)
	defer chCleanup()

	// 2. Pick free local ports for the collector components.
	otlpPort := freePort(t)
	healthPort := freePort(t)
	metricsExporterPort := freePort(t)

	// 3. Configure the collector with ClickHouse enabled and a short batch
	//    timeout (the default 30 s is too slow for a test).
	cfg := &config.Config{
		OTLPHTTPEndpoint:       fmt.Sprintf("0.0.0.0:%d", otlpPort),
		MetricsExporterPort:    metricsExporterPort,
		HealthCheckEndpoint:    fmt.Sprintf("0.0.0.0:%d", healthPort),
		ClickHouseEnabled:      true,
		ClickHouseAddr:         fmt.Sprintf("tcp://%s", chNativeAddr),
		ClickHouseDatabase:     "kvisor",
		ClickHouseUsername:     "kvisor",
		ClickHousePassword:     "kvisor",
		ClickHouseBatchTimeout: "2s",
	}

	collectorCtx, collectorCancel := context.WithCancel(ctx)
	defer collectorCancel()

	collectorErrCh := make(chan error, 1)
	go func() {
		collectorErrCh <- app.New(cfg, "test").Run(collectorCtx)
	}()

	// 4. Wait for the health-check extension to report ready.
	waitForCollectorHealthy(t, ctx, fmt.Sprintf("127.0.0.1:%d", healthPort))

	// 5. Send OTLP histogram metrics to the collector's OTLP HTTP receiver.
	sendTestOTLPMetrics(t, ctx, fmt.Sprintf("127.0.0.1:%d", otlpPort))

	// 6. Open a direct ClickHouse connection and assert the rows are present.
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{chNativeAddr},
		Auth: clickhouse.Auth{
			Database: "kvisor",
			Username: "kvisor",
			Password: "kvisor",
		},
	})
	r.NoError(err)
	defer conn.Close()

	assertMetricInClickHouse(t, ctx, conn)

	// 7. Shut down the collector and confirm it exits cleanly.
	collectorCancel()
	select {
	case collErr := <-collectorErrCh:
		if collErr != nil && !errors.Is(collErr, context.Canceled) {
			t.Errorf("collector exited with unexpected error: %v", collErr)
		}
	case <-time.After(10 * time.Second):
		t.Error("collector did not stop within 10 s after context cancel — possible goroutine or connection leak")
	}
}

// sendTestOTLPMetrics creates a MeterProvider backed by an OTLP HTTP exporter
// and records several http.server.request.duration histogram measurements.
// That metric name matches the golden-signal filter in the collector pipeline
// and will therefore be forwarded to ClickHouse.
func sendTestOTLPMetrics(t *testing.T, ctx context.Context, endpoint string) {
	t.Helper()

	exp, err := otlpmetrichttp.New(ctx,
		otlpmetrichttp.WithEndpoint(endpoint),
		otlpmetrichttp.WithInsecure(),
		// Use DELTA temporality so the cumulativetodelta processor passes data
		// through on the very first export cycle instead of treating it as the
		// initial cumulative baseline and dropping it.
		otlpmetrichttp.WithTemporalitySelector(func(_ sdkmetric.InstrumentKind) metricdata.Temporality {
			return metricdata.DeltaTemporality
		}),
	)
	require.NoError(t, err)

	res := sdkresource.NewSchemaless(
		attribute.String("service.name", "test-service"),
	)

	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exp,
			sdkmetric.WithInterval(500*time.Millisecond),
		)),
	)
	defer func() {
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutCancel()
		require.NoError(t, provider.Shutdown(shutCtx), "MeterProvider.Shutdown must flush all pending metrics")
	}()

	meter := provider.Meter("test-instrumentation")
	hist, err := meter.Float64Histogram(
		"http.server.request.duration",
		otelmetric.WithUnit("s"),
		otelmetric.WithDescription("Duration of HTTP server requests"),
	)
	require.NoError(t, err)

	// Record 10 observations at different latency buckets.
	durations := []float64{0.005, 0.010, 0.025, 0.050, 0.100, 0.200, 0.300, 0.500, 1.0, 2.5}
	for _, d := range durations {
		hist.Record(ctx, d,
			otelmetric.WithAttributes(
				attribute.String("http.method", "GET"),
				attribute.Int("http.response.status_code", 200),
			),
		)
	}

	// Allow two export cycles so the periodic reader has definitely sent data.
	time.Sleep(2 * time.Second)

	flushCtx, flushCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer flushCancel()
	require.NoError(t, provider.ForceFlush(flushCtx))
}

// assertMetricInClickHouse polls otel_metrics_histogram until it finds a row
// for http.server.request.duration, then asserts the key field values.
func assertMetricInClickHouse(t *testing.T, ctx context.Context, conn clickhouse.Conn) {
	t.Helper()

	r := require.New(t)
	deadline := time.After(30 * time.Second)
	var lastQueryErr error

	for {
		select {
		case <-ctx.Done():
			t.Fatal("context cancelled while waiting for metrics in ClickHouse")
			return
		case <-deadline:
			if lastQueryErr != nil {
				t.Fatalf("timed out (30 s) waiting for http.server.request.duration; last query error: %v", lastQueryErr)
			}
			t.Fatal("timed out (30 s) waiting for http.server.request.duration in otel_metrics_histogram")
			return
		case <-time.After(1 * time.Second):
			rows, queryErr := conn.Query(ctx, `
				SELECT MetricName, ServiceName, Count, Sum
				FROM kvisor.otel_metrics_histogram
				WHERE MetricName = 'http.server.request.duration'
				LIMIT 10`)
			if queryErr != nil {
				// Table may not exist yet while the collector is still initialising.
				lastQueryErr = queryErr
				t.Logf("query error (will retry): %v", queryErr)
				continue
			}

			var found bool
			for rows.Next() {
				var metricName, serviceName string
				var count uint64
				var sum float64
				if scanErr := rows.Scan(&metricName, &serviceName, &count, &sum); scanErr != nil {
					t.Logf("scan error (will retry): %v", scanErr)
					continue
				}
				r.Equal("http.server.request.duration", metricName)
				r.Equal("test-service", serviceName)

				r.Greater(count, uint64(0), "Count must be positive")
				r.Greater(sum, 0.0, "Sum must be positive")

				t.Logf("%v %v %v %v", metricName, serviceName, count, sum)
				found = true
			}
			if iterErr := rows.Err(); iterErr != nil {
				t.Logf("rows iteration error (will retry): %v", iterErr)
				if closeErr := rows.Close(); closeErr != nil {
					t.Logf("rows.Close error after iteration error: %v", closeErr)
				}
				continue
			}
			if closeErr := rows.Close(); closeErr != nil {
				t.Logf("rows.Close error (will retry): %v", closeErr)
				continue
			}

			if found {
				return
			}
			t.Log("no rows yet, retrying…")
		}
	}
}

// waitForCollectorHealthy polls the OTel health-check extension until it
// returns HTTP 200 or the context expires.
func waitForCollectorHealthy(t *testing.T, ctx context.Context, addr string) {
	t.Helper()

	client := &http.Client{Timeout: 1 * time.Second}
	for {
		select {
		case <-ctx.Done():
			t.Fatal("timed out waiting for OTel collector health check")
			return
		case <-time.After(200 * time.Millisecond):
			resp, err := client.Get("http://" + addr)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					return
				}
			}
		}
	}
}

// freePort binds to port 0, reads the assigned ephemeral port, closes the
// listener and returns the port number. There is a small TOCTOU window but it
// is negligible in a test context.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close(), "freePort: failed to release ephemeral listener")
	return port
}

func startClickhouseDB(t *testing.T) (string, func()) {
	ctx := context.Background()
	hz := wait.NewHTTPStrategy("/ping")
	hz.Port = "8123/tcp"
	req := testcontainers.ContainerRequest{
		Image:        "clickhouse/clickhouse-server:24.2.3.70-alpine",
		ExposedPorts: []string{"9000/tcp", "8123/tcp"},
		WaitingFor:   hz,
		Env: map[string]string{
			"CLICKHOUSE_USER":                      "kvisor",
			"CLICKHOUSE_PASSWORD":                  "kvisor",
			"CLICKHOUSE_DB":                        "kvisor",
			"CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT": "1",
		},
	}
	cont, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatal(err)
	}
	mport, err := cont.MappedPort(ctx, "9000/tcp")
	if err != nil {
		t.Fatal(err)
	}
	return "127.0.0.1:" + mport.Port(), func() {
		if err := cont.Terminate(ctx); err != nil {
			t.Fatalf("failed to terminate container: %s", err.Error())
		}
	}
}
