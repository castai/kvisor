package enrichment

import (
	"context"
	"testing"
	"time"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/stretchr/testify/require"
)

func TestEnrichmentService(t *testing.T) {
	t.Run("should enrich event", func(t *testing.T) {
		r := require.New(t)
		var wantedPID uint32 = 99

		svc := NewService(logging.New(&logging.Config{}), Config{
			WorkerCount: 1,
			EventEnrichers: []EventEnricher{
				enricherFrom(func(ctx context.Context, req *EnrichedContainerEvent) {
					req.Event.Pid = wantedPID
				}, castpb.EventType_UNKNOWN),
			},
		})

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		done := make(chan struct{})

		go func() {
			svc.Run(ctx)
			done <- struct{}{}
		}()

		event := &castpb.ContainerEvent{
			EventType: castpb.EventType_UNKNOWN,
			Pid:       99,
		}
		enqueued := svc.Enqueue(&EnrichedContainerEvent{
			Event:     event,
			EbpfEvent: &types.Event{},
		})
		r.True(enqueued)

		select {
		case event := <-svc.Events():
			r.Equal(wantedPID, event.Event.Pid)

		case <-ctx.Done():
			r.FailNow("timed out waiting for event")
		}

		cancel()

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			r.FailNow("timed out waiting for service to stop")
		}
	})
}

func enricherFrom(f func(context.Context, *EnrichedContainerEvent), eventTypes ...castpb.EventType) EventEnricher {
	return &functionEnricher{
		f:          f,
		eventTypes: eventTypes,
	}
}

type functionEnricher struct {
	f          func(context.Context, *EnrichedContainerEvent)
	eventTypes []castpb.EventType
}

func (e *functionEnricher) Enrich(ctx context.Context, req *EnrichedContainerEvent) {
	e.f(ctx, req)
}

func (e *functionEnricher) EventTypes() []castpb.EventType {
	return e.eventTypes
}
