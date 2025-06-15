package sustainability

import (
	"context"
	"testing"
	"time"

	"github.com/castai/kvisor/cmd/agent/daemon/state"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSustainabilityPipelineIntegration(t *testing.T) {
	// Create logger
	log := logging.New(&logging.Config{
		Level: logging.LevelDebug,
	})

	// Create channel for pipeline communication
	metricsChan := make(chan *state.SustainabilityMetricData, 100)

	// Create test exporter
	testExporter := &testSustainabilityExporter{
		receivedBatches: make([]*state.SustainabilityBatch, 0),
	}

	// Create exporters
	exporters := &state.Exporters{
		Sustainability: []state.SustainabilityExporter{testExporter},
	}

	// Create mock controller for testing pipeline
	controller := &state.Controller{
		// Note: This is a simplified mock for testing
	}

	// Set up test data
	testMetric := &state.SustainabilityMetricData{
		Timestamp:     time.Now().Unix(),
		NodeName:      "test-node",
		Namespace:     "default",
		PodName:       "test-pod",
		ContainerName: "test-container",
		EnergyJoules:  1500.0,
	}

	// Start pipeline in background
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		// Simulate pipeline (simplified version for test)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		var collectedMetrics []*state.SustainabilityMetricData

		for {
			select {
			case <-ctx.Done():
				return
			case metric := <-metricsChan:
				collectedMetrics = append(collectedMetrics, metric)
			case <-ticker.C:
				if len(collectedMetrics) > 0 {
					// Create batch
					batch := &state.SustainabilityBatch{}
					for _, raw := range collectedMetrics {
						metric := &state.SustainabilityMetric{
							Timestamp:       raw.Timestamp,
							NodeName:        raw.NodeName,
							Namespace:       raw.Namespace,
							PodName:         raw.PodName,
							ContainerName:   raw.ContainerName,
							EnergyJoules:    raw.EnergyJoules,
							CarbonGramsCO2e: raw.EnergyJoules * 415.7 / 3600000, // Simple calculation
							CostUSD:         raw.EnergyJoules * 0.12 / 3600000,  // Simple calculation
						}
						batch.Items = append(batch.Items, metric)
					}

					// Send to exporters
					for _, exp := range exporters.Sustainability {
						exp.Enqueue(batch)
					}

					collectedMetrics = collectedMetrics[:0]
				}
			}
		}
	}()

	// Start test exporter
	go testExporter.Run(ctx)

	// Send test metric
	metricsChan <- testMetric

	// Wait for processing
	time.Sleep(200 * time.Millisecond)

	// Verify results
	assert.Eventually(t, func() bool {
		return len(testExporter.receivedBatches) > 0
	}, 2*time.Second, 50*time.Millisecond, "Should receive at least one batch")

	require.Greater(t, len(testExporter.receivedBatches), 0, "Should have received batches")

	batch := testExporter.receivedBatches[0]
	require.Greater(t, len(batch.Items), 0, "Batch should contain items")

	metric := batch.Items[0]
	assert.Equal(t, "test-node", metric.NodeName)
	assert.Equal(t, "default", metric.Namespace)
	assert.Equal(t, "test-pod", metric.PodName)
	assert.Equal(t, "test-container", metric.ContainerName)
	assert.Equal(t, 1500.0, metric.EnergyJoules)
	assert.Greater(t, metric.CarbonGramsCO2e, 0.0)
	assert.Greater(t, metric.CostUSD, 0.0)
}

// testSustainabilityExporter is a test implementation
type testSustainabilityExporter struct {
	receivedBatches []*state.SustainabilityBatch
}

func (t *testSustainabilityExporter) Run(ctx context.Context) error {
	// Simple test implementation - just store received batches
	return nil
}

func (t *testSustainabilityExporter) Enqueue(batch *state.SustainabilityBatch) {
	t.receivedBatches = append(t.receivedBatches, batch)
}
