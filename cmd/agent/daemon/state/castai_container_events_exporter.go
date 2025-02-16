package state

import (
	"context"
	"log/slog"
	"time"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/metrics"
	"github.com/castai/kvisor/pkg/castai"
	"github.com/castai/kvisor/pkg/logging"
	"google.golang.org/grpc"
)

type ContainerEventsSender interface {
	Send(ctx context.Context, batch *castpb.ContainerEventsBatch) error
}

func NewCastaiContainerEventSender(ctx context.Context, log *logging.Logger, apiClient *castai.Client) *CastaiContainerEventSender {
	ws := castai.NewWriteStream[*castpb.ContainerEventsBatch, *castpb.WriteStreamResponse](ctx, func(ctx context.Context) (grpc.ClientStream, error) {
		return apiClient.GRPC.ContainerEventsBatchWriteStream(ctx, grpc.UseCompressor(apiClient.GetCompressionName()))
	})
	defer ws.Close()
	ws.ReopenDelay = 2 * time.Second

	return &CastaiContainerEventSender{
		log: log,
		ws:  ws,
	}
}

type CastaiContainerEventSender struct {
	log *logging.Logger
	ws  *castai.WriteStream[*castpb.ContainerEventsBatch, *castpb.WriteStreamResponse]
}

func (s *CastaiContainerEventSender) Send(ctx context.Context, batch *castpb.ContainerEventsBatch) error {
	err := s.send(batch)
	if err != nil {
		if s.log.IsEnabled(slog.LevelDebug) {
			s.log.Errorf("sending batch: %v", err)
		}
		metrics.AgentExporterSendErrorsTotal.WithLabelValues("castai_container_events").Inc()
		return err
	}
	metrics.AgentExporterSendTotal.WithLabelValues("container_events_batch").Inc()
	metrics.AgentExporterSendTotal.WithLabelValues("container_events_batch_items").Add(float64(len(batch.Items)))
	return nil
}

func (s *CastaiContainerEventSender) send(batch *castpb.ContainerEventsBatch) error {
	var err error
	for range 2 {
		err = s.ws.Send(batch)
		if err != nil {
			continue
		}
		return nil
	}
	return err
}
