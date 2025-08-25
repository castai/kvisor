package state

import (
	"context"
	"time"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/metrics"
	"github.com/castai/kvisor/pkg/castai"
	"github.com/castai/kvisor/pkg/logging"
	"google.golang.org/grpc"
)

func NewCastaiSustainabilityExporter(log *logging.Logger, apiClient *castai.Client, queueSize int) *CastaiSustainabilityExporter {
	return &CastaiSustainabilityExporter{
		log:                         log.WithField("component", "castai_sustainability_exporter"),
		apiClient:                   apiClient,
		queue:                       make(chan *castpb.StatsBatch, queueSize),
		writeStreamCreateRetryDelay: 1 * time.Second,
		drainTimeout:                5 * time.Second,
	}
}

type CastaiSustainabilityExporter struct {
	log                         *logging.Logger
	apiClient                   *castai.Client
	queue                       chan *castpb.StatsBatch
	writeStreamCreateRetryDelay time.Duration
	drainTimeout                time.Duration
}

func (c *CastaiSustainabilityExporter) Run(rootCtx context.Context) error {
	c.log.Info("running sustainability export loop")
	defer c.log.Info("sustainability export loop done")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ws := castai.NewWriteStream[*castpb.StatsBatch, *castpb.WriteStreamResponse](ctx, func(ctx context.Context) (grpc.ClientStream, error) {
		return c.apiClient.GRPC.StatsWriteStream(ctx, grpc.UseCompressor(c.apiClient.GetCompressionName()))
	})
	defer ws.Close()
	ws.ReopenDelay = c.writeStreamCreateRetryDelay

	sendErrorMetric := metrics.AgentExporterSendErrorsTotal.WithLabelValues("castai_sustainability")
	sendMetric := metrics.AgentExporterSendTotal.WithLabelValues("castai_sustainability")

	sendWithRetry := func(e *castpb.StatsBatch) {
		for range 2 {
			if err := ws.Send(e); err != nil {
				continue
			}
			sendMetric.Inc()
			return
		}
		sendErrorMetric.Inc()
	}

	// Drain and send remaining data.
	defer func() {
		drainCtx, cancel := context.WithTimeout(context.Background(), c.drainTimeout)
		defer cancel()
		for len(c.queue) > 0 {
			select {
			case <-drainCtx.Done():
				return
			default:
			}
			sendWithRetry(<-c.queue)
		}
		cancel()
	}()

	for {
		select {
		case <-rootCtx.Done():
			return rootCtx.Err()
		case e := <-c.queue:
			sendWithRetry(e)
		}
	}
}

func (c *CastaiSustainabilityExporter) Enqueue(batch *castpb.StatsBatch) {
	select {
	case c.queue <- batch:
	default:
		metrics.AgentExporterQueueDroppedTotal.WithLabelValues("castai_sustainability").Inc()
		c.log.Warn("sustainability export queue full, dropping batch")
	}
}
