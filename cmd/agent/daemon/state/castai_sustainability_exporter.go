package state

import (
	"context"
	"time"

	"github.com/castai/kvisor/cmd/agent/daemon/metrics"
	"github.com/castai/kvisor/pkg/castai"
	"github.com/castai/kvisor/pkg/logging"
)

func NewCastaiSustainabilityExporter(log *logging.Logger, apiClient *castai.Client, queueSize int) *CastaiSustainabilityExporter {
	return &CastaiSustainabilityExporter{
		log:                         log.WithField("component", "castai_sustainability_exporter"),
		apiClient:                   apiClient,
		queue:                       make(chan *SustainabilityBatch, queueSize),
		writeStreamCreateRetryDelay: 1 * time.Second,
		drainTimeout:                5 * time.Second,
	}
}

type CastaiSustainabilityExporter struct {
	log                         *logging.Logger
	apiClient                   *castai.Client
	queue                       chan *SustainabilityBatch
	writeStreamCreateRetryDelay time.Duration
	drainTimeout                time.Duration
}

func (c *CastaiSustainabilityExporter) Run(rootCtx context.Context) error {
	c.log.Info("running sustainability export loop")
	defer c.log.Info("sustainability export loop done")

	// For now, log that we would send to CAST AI but implementation is pending
	// until SustainabilityStats protobuf is properly generated
	for {
		select {
		case <-rootCtx.Done():
			return rootCtx.Err()
		case batch := <-c.queue:
			// TODO: Implement actual gRPC stream to CAST AI once SustainabilityStats protobuf is available
			// For now, we log the metrics that would be sent
			c.log.Infof("Would send to CAST AI: %d sustainability metrics", len(batch.Items))
			for _, item := range batch.Items {
				c.log.Debugf("Would send: namespace=%s pod=%s container=%s energy=%.2fJ carbon=%.2fgCO2e cost=$%.6f",
					item.Namespace, item.PodName, item.ContainerName,
					item.EnergyJoules, item.CarbonGramsCO2e, item.CostUSD)
			}
			metrics.AgentExporterSendTotal.WithLabelValues("castai_sustainability").Add(float64(len(batch.Items)))
		}
	}
}

func (c *CastaiSustainabilityExporter) Enqueue(batch *SustainabilityBatch) {
	select {
	case c.queue <- batch:
	default:
		// Follow kvisor pattern for dropped metrics
		metrics.AgentExporterQueueDroppedTotal.WithLabelValues("castai_sustainability").Inc()
		c.log.Warn("sustainability export queue full, dropping batch")
	}
}
