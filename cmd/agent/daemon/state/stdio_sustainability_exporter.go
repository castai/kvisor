package state

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/castai/kvisor/cmd/agent/daemon/metrics"
	"github.com/castai/kvisor/pkg/logging"
)

func NewStdioSustainabilityExporter(log *logging.Logger, queueSize int) *StdioSustainabilityExporter {
	return &StdioSustainabilityExporter{
		log:   log.WithField("component", "stdio_sustainability_exporter"),
		queue: make(chan *SustainabilityBatch, queueSize),
	}
}

type StdioSustainabilityExporter struct {
	log   *logging.Logger
	queue chan *SustainabilityBatch
}

func (c *StdioSustainabilityExporter) Run(ctx context.Context) error {
	c.log.Info("running sustainability export loop")
	defer c.log.Info("sustainability export loop done")

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case batch := <-c.queue:
			// Print metrics using kvisor's simple logging pattern
			for _, metric := range batch.Items {
				// Log summary in kvisor style
				c.log.Infof("sustainability: namespace=%s pod=%s container=%s energy=%.2fJ carbon=%.2fgCO2e cost=$%.6f",
					metric.Namespace, metric.PodName, metric.ContainerName,
					metric.EnergyJoules, metric.CarbonGramsCO2e, metric.CostUSD)

				// Print JSON for external systems
				jsonData, err := json.Marshal(metric)
				if err != nil {
					c.log.Errorf("failed to marshal sustainability metric: %v", err)
					continue
				}
				fmt.Printf("SUSTAINABILITY_METRIC: %s\n", string(jsonData))
			}
		}
	}
}

func (c *StdioSustainabilityExporter) Enqueue(batch *SustainabilityBatch) {
	select {
	case c.queue <- batch:
	default:
		// Follow kvisor pattern for dropped metrics
		metrics.AgentExporterQueueDroppedTotal.WithLabelValues("stdio_sustainability").Inc()
		c.log.Warn("sustainability export queue full, dropping batch")
	}
}
