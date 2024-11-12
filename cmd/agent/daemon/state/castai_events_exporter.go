package state

import (
	"context"
	"fmt"
	"time"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/castai"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/castai/kvisor/pkg/metrics"
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
	if e.GetEventType().String() == "EVENT_TCP_CONNECT" {
		fmt.Println("sending event of type EVENT_TCP_CONNECT")
	}

	if err := s.ws.Send(e); err != nil {
		if retry {
			if e.GetEventType().String() == "EVENT_TCP_CONNECT" {
				fmt.Println("retrying event of type EVENT_TCP_CONNECT")
			}
			s.retryQueue <- e

			return
		}

		if e.GetEventType().String() == "EVENT_TCP_CONNECT" {
			fmt.Println("failed to send event of type EVENT_TCP_CONNECT")
		}

		s.sendErrorMetric.Inc()
		return
	}

	if e.GetEventType().String() == "EVENT_TCP_CONNECT" {
		fmt.Println("succsefully sent event of type EVENT_TCP_CONNECT")
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
