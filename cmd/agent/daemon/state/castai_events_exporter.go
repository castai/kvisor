package state

import (
	"context"
	"time"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/castai"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/castai/kvisor/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
)

func NewCastaiEventsExporter(log *logging.Logger, apiClient *castai.Client) *CastaiEventsExporter {
	return &CastaiEventsExporter{
		log:                         log.WithField("component", "castai_events_exporter"),
		apiClient:                   apiClient,
		queue:                       make(chan *castpb.Event, 1000),
		writeStreamCreateRetryDelay: 2 * time.Second,
	}
}

type CastaiEventsExporter struct {
	log                         *logging.Logger
	apiClient                   *castai.Client
	queue                       chan *castpb.Event
	writeStreamCreateRetryDelay time.Duration
}

func (c *CastaiEventsExporter) Run(ctx context.Context) error {
	c.log.Info("running export loop")
	defer c.log.Info("export loop done")

	ws := castai.NewWriteStream[*castpb.Event, *castpb.WriteStreamResponse](ctx, func(ctx context.Context) (grpc.ClientStream, error) {
		return c.apiClient.GRPC.EventsWriteStream(ctx)
	})
	defer ws.Close()
	ws.ReopenDelay = c.writeStreamCreateRetryDelay

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e := <-c.queue:
			if err := ws.Send(e); err != nil {
				continue
			}
			metrics.AgentExportedEventsTotal.With(prometheus.Labels{metrics.EventTypeLabel: e.GetEventType().String()}).Inc()
		}
	}
}

func (c *CastaiEventsExporter) Enqueue(e *castpb.Event) {
	select {
	case c.queue <- e:
	default:
		// TODO: metric
	}
}
