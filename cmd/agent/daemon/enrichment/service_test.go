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
		wantedPodUID := "pod-uid-1"
		wantedPodName := "this-is-pod-1"

		svc := NewService(logging.New(&logging.Config{}), Config{
			WorkerCount: 1,
			EventEnrichers: []EventEnricher{
				enricherFrom(func(ctx context.Context, req *EnrichRequest) {
					req.Event.PodName = wantedPodName
				}, castpb.EventType_UNKNOWN),
				enricherFrom(func(ctx context.Context, req *EnrichRequest) {
					req.Event.PodUid = wantedPodUID
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

		event := &castpb.Event{
			EventType: castpb.EventType_UNKNOWN,
			PodUid:    "uid-1",
			PodName:   "pod-1",
		}
		enqueued := svc.Enqueue(&EnrichRequest{
			Event:     event,
			EbpfEvent: &types.Event{},
		})
		r.True(enqueued)

		select {
		case event := <-svc.Events():
			r.Equal(wantedPodUID, event.PodUid)
			r.Equal(wantedPodName, event.PodName)

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

func enricherFrom(f func(context.Context, *EnrichRequest), eventTypes ...castpb.EventType) EventEnricher {
	return &functionEnricher{
		f:          f,
		eventTypes: eventTypes,
	}
}

type functionEnricher struct {
	f          func(context.Context, *EnrichRequest)
	eventTypes []castpb.EventType
}

func (e *functionEnricher) Enrich(ctx context.Context, req *EnrichRequest) {
	e.f(ctx, req)
}

func (e *functionEnricher) EventTypes() []castpb.EventType {
	return e.eventTypes
}
