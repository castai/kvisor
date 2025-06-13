package pipeline

import (
	"context"
	"time"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/metrics"
	"github.com/castai/kvisor/pkg/castai"
	"github.com/castai/kvisor/pkg/logging"
	"google.golang.org/grpc"
)

type castaiNetflowExporterClient interface {
	NetflowWriteStream(ctx context.Context, opts ...grpc.CallOption) (castpb.RuntimeSecurityAgentAPI_NetflowWriteStreamClient, error)
	GetCompressionName() string
}

func NewCastaiNetflowExporter(log *logging.Logger, apiClient castaiNetflowExporterClient, queueSize int) *CastaiNetflowExporter {
	return &CastaiNetflowExporter{
		log:                         log.WithField("component", "castai_netflow_exporter"),
		apiClient:                   apiClient,
		queue:                       make(chan *castpb.Netflow, queueSize),
		writeStreamCreateRetryDelay: 1 * time.Second,
		drainTimeout:                5 * time.Second,
	}
}

type CastaiNetflowExporter struct {
	log                         *logging.Logger
	apiClient                   castaiNetflowExporterClient
	queue                       chan *castpb.Netflow
	writeStreamCreateRetryDelay time.Duration
	drainTimeout                time.Duration
}

func (c *CastaiNetflowExporter) Run(rootCtx context.Context) error {
	c.log.Info("running export loop")
	defer c.log.Info("export loop done")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ws := castai.NewWriteStream[*castpb.Netflow, *castpb.WriteStreamResponse](ctx, func(ctx context.Context) (grpc.ClientStream, error) {
		return c.apiClient.NetflowWriteStream(ctx, grpc.UseCompressor(c.apiClient.GetCompressionName()))
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

func (c *CastaiNetflowExporter) Enqueue(e *castpb.Netflow) {
	select {
	case c.queue <- e:
	default:
		metrics.AgentExporterQueueDroppedTotal.WithLabelValues("castai_netflow").Inc()
	}
}
