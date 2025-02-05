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

type castaiNetflowExporterClient interface {
	NetflowWriteStream(ctx context.Context, opts ...grpc.CallOption) (castpb.RuntimeSecurityAgentAPI_NetflowWriteStreamClient, error)
}

func NewCastaiNetflowExporter(log *logging.Logger, apiClient castaiNetflowExporterClient, queueSize int) *CastaiNetflowExporter {
	return &CastaiNetflowExporter{
		log:                         log.WithField("component", "castai_netflow_exporter"),
		apiClient:                   apiClient,
		queue:                       make(chan *castpb.Netflow, queueSize),
		writeStreamCreateRetryDelay: 1 * time.Second,
	}
}

type CastaiNetflowExporter struct {
	log                         *logging.Logger
	apiClient                   castaiNetflowExporterClient
	queue                       chan *castpb.Netflow
	writeStreamCreateRetryDelay time.Duration
}

func (c *CastaiNetflowExporter) Run(ctx context.Context) error {
	c.log.Info("running export loop")
	defer c.log.Info("export loop done")

	ws := castai.NewWriteStream[*castpb.Netflow, *castpb.WriteStreamResponse](ctx, func(ctx context.Context) (grpc.ClientStream, error) {
		return c.apiClient.NetflowWriteStream(ctx, grpc.UseCompressor(gzip.Name))
	})
	defer ws.Close()
	ws.ReopenDelay = c.writeStreamCreateRetryDelay

	sendErrorMetric := metrics.AgentExporterSendErrorsTotal.WithLabelValues("castai_netflow")
	sendMetric := metrics.AgentExporterSendTotal.WithLabelValues("castai_netflow")

	sendWithRetry := func(e *castpb.Netflow) {
		for range 2 {
			if err := ws.Send(e); err != nil {
				continue
			}
			sendMetric.Inc()
			return
		}
		sendErrorMetric.Inc()
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e := <-c.queue:
			sendWithRetry(e)
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
