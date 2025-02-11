package state

import (
	"context"
	"log/slog"
	"testing"
	"time"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/containers"
	"github.com/castai/kvisor/pkg/ebpftracer/events"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/logging"
)

func BenchmarkContainerEventsGroup(b *testing.B) {
	ctx := context.Background()
	enricher := &mockEnrichmentService{}
	exporter := &mockContainerEventsSender{}
	cfg := containerEventsGroupConfig{
		batchSize:     1000,
		flushInterval: 1 * time.Second,
	}
	now := time.Now
	var mapper containerEventMapper = func(res *castaipb.ContainerEvent, e *types.Event, signatureEvent *castaipb.SignatureEvent) {
	}

	batch := &castaipb.ContainerEventsBatch{}

	e := &types.Event{
		Context: &types.EventContext{EventID: events.Write, Ts: 1, CgroupID: 1},
		Container: &containers.Container{
			PodName: "p0",
		},
		Args: &types.SchedProcessExecArgs{
			Filename: "/bin/curl",
			Argv:     []string{`Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.`},
		},
	}

	b.Run("handle events", func(b *testing.B) {
		log := logging.New(&logging.Config{Level: slog.LevelInfo})
		g := newContainerEventsGroup(log, enricher, exporter, batch, cfg, now, mapper, &mockEbpfTracer{})
		handleEvents := func() {
			for range 1000 {
				g.handleEvent(ctx, e, nil)
			}
		}
		handleEvents()

		b.ResetTimer()
		b.ReportAllocs()
		for n := 0; n < b.N; n++ {
			handleEvents()
		}
	})
}
