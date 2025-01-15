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

func NewCastaiStatsExporter(log *logging.Logger, apiClient *castai.Client, queueSize int) *CastaiStatsExporter {
	return &CastaiStatsExporter{
		log:                         log.WithField("component", "castai_stats_exporter"),
		apiClient:                   apiClient,
		queue:                       make(chan *castpb.StatsBatch, queueSize),
		writeStreamCreateRetryDelay: 2 * time.Second,
	}
}

type CastaiStatsExporter struct {
	log                         *logging.Logger
	apiClient                   *castai.Client
	queue                       chan *castpb.StatsBatch
	writeStreamCreateRetryDelay time.Duration
}

func (c *CastaiStatsExporter) Run(ctx context.Context) error {
	c.log.Info("running export loop")
	defer c.log.Info("export loop done")

	ws := castai.NewWriteStream[*castpb.StatsBatch, *castpb.WriteStreamResponse](ctx, func(ctx context.Context) (grpc.ClientStream, error) {
		return c.apiClient.GRPC.StatsWriteStream(ctx)
	})
	defer ws.Close()
	ws.ReopenDelay = c.writeStreamCreateRetryDelay

	sendErrorMetric := metrics.AgentExporterSendErrorsTotal.WithLabelValues("castai_stats")
	sendMetric := metrics.AgentExporterSendTotal.WithLabelValues("castai_stats")

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e := <-c.queue:
			if err := ws.Send(e); err != nil {
				sendErrorMetric.Inc()
				continue
			}
			sendMetric.Inc()
		}
	}
}

func (c *CastaiStatsExporter) Enqueue(e *castpb.StatsBatch) {
	select {
	case c.queue <- e:
	default:
		metrics.AgentExporterQueueDroppedTotal.WithLabelValues("castai_stats").Inc()
	}
}
