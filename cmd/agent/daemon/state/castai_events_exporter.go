package state

import (
	"context"
	"time"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/metrics"
	"github.com/castai/kvisor/pkg/castai"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
)

func NewCastaiEventsExporter(log *logging.Logger, apiClient *castai.Client, queueSize int) *CastaiEventsExporter {
	return &CastaiEventsExporter{
		log:                         log.WithField("component", "castai_events_exporter"),
		apiClient:                   apiClient,
		queue:                       make(chan *castpb.Event, queueSize),
		retryQueue:                  make(chan *castpb.Event, queueSize/10),
		writeStreamCreateRetryDelay: 2 * time.Second,
	}
}

type CastaiEventsExporter struct {
	log       *logging.Logger
	apiClient *castai.Client
	queue     chan *castpb.Event
	// retryQueue is a queue in which we'll push events that failed to send.
	// It is a separate queue to give failed events a priority,
	// instead of sending them to the back of the original queue.
	retryQueue                  chan *castpb.Event
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

	sender := &eventSender{
		ws:              ws,
		retryQueue:      c.retryQueue,
		sendMetric:      metrics.AgentExporterSendTotal.WithLabelValues("castai_events"),
		sendErrorMetric: metrics.AgentExporterSendErrorsTotal.WithLabelValues("castai_events"),
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e := <-c.queue:
			sender.send(e, true)
		case e := <-c.retryQueue:
			sender.send(e, false)
		}
	}
}

type eventSender struct {
	ws         *castai.WriteStream[*castpb.Event, *castpb.WriteStreamResponse]
	retryQueue chan *castpb.Event

	sendMetric      prometheus.Counter
	sendErrorMetric prometheus.Counter
}

func (s *eventSender) send(e *castpb.Event, retry bool) {
	if err := s.ws.Send(e); err != nil {
		if retry {
			s.retryQueue <- e

			return
		}

		s.sendErrorMetric.Inc()
		return
	}

	s.sendMetric.Inc()
	metrics.AgentExportedEventsTotal.With(prometheus.Labels{metrics.EventTypeLabel: e.GetEventType().String()}).Inc()
}

func (c *CastaiEventsExporter) Enqueue(e *castpb.Event) {
	select {
	case c.queue <- e:
	default:
		metrics.AgentExporterQueueDroppedTotal.WithLabelValues("castai_events").Inc()
	}
}
