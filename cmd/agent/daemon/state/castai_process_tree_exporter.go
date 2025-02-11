package state

import (
	"context"
	"time"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/metrics"
	"github.com/castai/kvisor/pkg/castai"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/castai/kvisor/pkg/processtree"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
)

const (
	castaiProcessTreeLabel = "castai_process_tree"
)

type CastaiProcessTreeExporter struct {
	log       *logging.Logger
	apiClient *castai.Client
	queue     chan processtree.ProcessTreeEvent
	// retryQueue is a queue in which we'll push events that failed to send.
	// It is a separate queue to give failed events a priority,
	// instead of sending them to the back of the original queue.
	retryQueue                  chan *castpb.ProcessTreeEvent
	writeStreamCreateRetryDelay time.Duration
}

func NewCastaiProcessTreeExporter(log *logging.Logger, apiClient *castai.Client, queueSize int) *CastaiProcessTreeExporter {
	return &CastaiProcessTreeExporter{
		log:                         log.WithField("component", "castai_process_tree_exporter"),
		apiClient:                   apiClient,
		queue:                       make(chan processtree.ProcessTreeEvent, queueSize),
		retryQueue:                  make(chan *castpb.ProcessTreeEvent, queueSize/10),
		writeStreamCreateRetryDelay: 2 * time.Second,
	}
}

func (c *CastaiProcessTreeExporter) Enqueue(e processtree.ProcessTreeEvent) {
	select {
	case c.queue <- e:
	default:
		metrics.AgentExporterQueueDroppedTotal.WithLabelValues(castaiProcessTreeLabel).Inc()
	}
}

func (c *CastaiProcessTreeExporter) Run(ctx context.Context) error {
	c.log.Info("running process tree export loop")
	defer c.log.Info("export process tree loop done")

	ws := castai.NewWriteStream[*castpb.ProcessTreeEvent, *castpb.WriteStreamResponse](ctx, func(ctx context.Context) (grpc.ClientStream, error) {
		return c.apiClient.GRPC.ProcessEventsWriteStream(ctx, grpc.UseCompressor(c.apiClient.GetCompressionName()))
	})
	defer ws.Close()
	ws.ReopenDelay = c.writeStreamCreateRetryDelay

	sender := &processTreeSender{
		ws:              ws,
		retryQueue:      c.retryQueue,
		sendMetric:      metrics.AgentExporterSendTotal.WithLabelValues(castaiProcessTreeLabel),
		sendErrorMetric: metrics.AgentExporterSendErrorsTotal.WithLabelValues(castaiProcessTreeLabel),
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event := <-c.queue:
			e := toProtoProcessTreeEvent(event)
			sender.send(e, true)
		case e := <-c.retryQueue:
			sender.send(e, false)
		}
	}
}

func toProtoProcessTreeEvent(e processtree.ProcessTreeEvent) *castpb.ProcessTreeEvent {
	events := make([]*castpb.ProcessEvent, len(e.Events))

	for i, pe := range e.Events {
		events[i] = &castpb.ProcessEvent{
			Timestamp:   uint64(pe.Timestamp.UnixNano()), // nolint:gosec
			ContainerId: pe.ContainerID,
			Process: &castpb.Process{
				Pid:             pe.Process.PID,
				StartTime:       uint64(pe.Process.StartTime), // nolint:gosec
				Ppid:            pe.Process.PPID,
				ParentStartTime: uint64(pe.Process.ParentStartTime), // nolint:gosec
				Args:            pe.Process.Args,
				Filepath:        pe.Process.FilePath,
				ExitTime:        pe.Process.ExitTime,
			},
			Action: toProtoProcessAction(pe.Action),
		}
	}

	return &castpb.ProcessTreeEvent{
		Initial: e.Initial,
		Events:  events,
	}
}

func toProtoProcessAction(action processtree.ProcessAction) castpb.ProcessAction {
	switch action {
	case processtree.ProcessExec:
		return castpb.ProcessAction_PROCESS_ACTION_EXEC
	case processtree.ProcessFork:
		return castpb.ProcessAction_PROCESS_ACTION_FORK
	case processtree.ProcessExit:
		return castpb.ProcessAction_PROCESS_ACTION_EXIT
	}
	return castpb.ProcessAction_PROCESS_ACTION_UNKNOWN
}

type processTreeSender struct {
	ws         *castai.WriteStream[*castpb.ProcessTreeEvent, *castpb.WriteStreamResponse]
	retryQueue chan *castpb.ProcessTreeEvent

	sendMetric      prometheus.Counter
	sendErrorMetric prometheus.Counter
}

func (s *processTreeSender) send(e *castpb.ProcessTreeEvent, retry bool) {
	if err := s.ws.Send(e); err != nil {
		if retry {
			s.retryQueue <- e

			return
		}

		s.sendErrorMetric.Inc()
		return
	}

	s.sendMetric.Inc()
	metrics.AgentExportedEventsTotal.With(prometheus.Labels{metrics.EventTypeLabel: "process_tree"}).Inc()
}
