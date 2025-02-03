package state

import (
	"context"
	"time"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/metrics"
	"github.com/castai/kvisor/pkg/castai"
	"github.com/castai/kvisor/pkg/logging"
	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding/gzip"
)

func NewCastaiNetflowExporter(log *logging.Logger, apiClient *castai.Client, queueSize int) *CastaiNetflowExporter {
	return &CastaiNetflowExporter{
		log:                         log.WithField("component", "castai_netflow_exporter"),
		apiClient:                   apiClient,
		queue:                       make(chan *castpb.Netflow, queueSize),
		writeStreamCreateRetryDelay: 2 * time.Second,
	}
}

type CastaiNetflowExporter struct {
	log                         *logging.Logger
	apiClient                   *castai.Client
	queue                       chan *castpb.Netflow
	writeStreamCreateRetryDelay time.Duration
}

func (c *CastaiNetflowExporter) Run(ctx context.Context) error {
	c.log.Info("running export loop")
	defer c.log.Info("export loop done")

	ws := castai.NewWriteStream[*castpb.Netflow, *castpb.WriteStreamResponse](ctx, func(ctx context.Context) (grpc.ClientStream, error) {
		return c.apiClient.GRPC.NetflowWriteStream(ctx, grpc.UseCompressor(gzip.Name))
	})
	defer ws.Close()
	ws.ReopenDelay = c.writeStreamCreateRetryDelay

	sendErrorMetric := metrics.AgentExporterSendErrorsTotal.WithLabelValues("castai_netflow")
	sendMetric := metrics.AgentExporterSendTotal.WithLabelValues("castai_netflow")

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

func (c *CastaiNetflowExporter) Enqueue(e *castpb.Netflow) {
	select {
	case c.queue <- e:
	default:
		metrics.AgentExporterQueueDroppedTotal.WithLabelValues("castai_netflow").Inc()
	}
}
