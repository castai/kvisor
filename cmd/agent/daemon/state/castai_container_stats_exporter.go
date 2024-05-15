package state

import (
	"context"
	"time"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/castai"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/castai/kvisor/pkg/metrics"
	"google.golang.org/grpc"
)

func NewCastaiContainerStatsExporter(log *logging.Logger, apiClient *castai.Client, queueSize int) *CastaiContainerStatsExporter {
	return &CastaiContainerStatsExporter{
		log:                         log.WithField("component", "castai_container_stats_exporter"),
		apiClient:                   apiClient,
		queue:                       make(chan *castpb.ContainerStatsBatch, queueSize),
		writeStreamCreateRetryDelay: 2 * time.Second,
	}
}

type CastaiContainerStatsExporter struct {
	log                         *logging.Logger
	apiClient                   *castai.Client
	queue                       chan *castpb.ContainerStatsBatch
	writeStreamCreateRetryDelay time.Duration
}

func (c *CastaiContainerStatsExporter) Run(ctx context.Context) error {
	c.log.Info("running export loop")
	defer c.log.Info("export loop done")

	ws := castai.NewWriteStream[*castpb.ContainerStatsBatch, *castpb.WriteStreamResponse](ctx, func(ctx context.Context) (grpc.ClientStream, error) {
		return c.apiClient.GRPC.ContainerStatsWriteStream(ctx)
	})
	defer ws.Close()
	ws.ReopenDelay = c.writeStreamCreateRetryDelay

	sendErrorMetric := metrics.AgentExporterSendErrorsTotal.WithLabelValues("castai_container_stats")
	sendMetric := metrics.AgentExporterSendTotal.WithLabelValues("castai_container_stats")

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

func (c *CastaiContainerStatsExporter) Enqueue(e *castpb.ContainerStatsBatch) {
	select {
	case c.queue <- e:
	default:
		metrics.AgentExporterQueueDroppedTotal.WithLabelValues("castai_container_stats").Inc()
	}
}
