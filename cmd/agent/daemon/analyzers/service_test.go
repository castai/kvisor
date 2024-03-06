package analyzers

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/stretchr/testify/require"
)

func TestService(t *testing.T) {
	r := require.New(t)
	log := logging.New(&logging.Config{
		Level: slog.LevelDebug,
	})
	ctx := context.Background()

	t.Run("find suspicious binary", func(t *testing.T) {
		svc := newTestService(log)
		svc.Enqueue(&castpb.Event{
			EventType:   castpb.EventType_EVENT_EXEC,
			ContainerId: "c1",
			Data: &castpb.Event_Exec{
				Exec: &castpb.Exec{
					Path: "/xmrig.out",
				},
			},
		})

		errc := make(chan error, 1)
		go func() {
			errc <- svc.Run(ctx)
		}()

		select {
		case err := <-errc:
			t.Fatal(err)
		case res := <-svc.Results():
			r.Equal(castpb.Language_LANG_C, res.GetExec().Meta.Lang)
		case <-time.After(2 * time.Second):
			t.Fatal("timeout")
		}
	})

	t.Run("skip if no binary found", func(t *testing.T) {
		svc := newTestService(log)
		svc.Enqueue(&castpb.Event{
			EventType:   castpb.EventType_EVENT_EXEC,
			ContainerId: "c1",
			Data: &castpb.Event_Exec{
				Exec: &castpb.Exec{
					Path: "/not-found.out",
				},
			},
		})

		errc := make(chan error, 1)
		go func() {
			errc <- svc.Run(ctx)
		}()

		select {
		case err := <-errc:
			t.Fatal(err)
		case <-svc.Results():
			t.Fatal("expected no results")
		case <-time.After(100 * time.Millisecond):
			// Ok.
		}
	})

	t.Run("skip already processed paths", func(t *testing.T) {
		svc := newTestService(log)
		analyzer := &testAnalyzer{}
		svc.analyzers = []Analyzer{analyzer}
		for i := 0; i < 10; i++ {
			svc.Enqueue(&castpb.Event{
				EventType:   castpb.EventType_EVENT_EXEC,
				ContainerId: "c1",
				Data: &castpb.Event_Exec{
					Exec: &castpb.Exec{
						Path: "/xmrig.out",
					},
				},
			})
		}

		errc := make(chan error, 1)
		go func() {
			errc <- svc.Run(ctx)
		}()

		select {
		case err := <-errc:
			t.Fatal(err)
		case <-svc.Results():
			r.Equal(analyzer.calls.Load(), int32(1))
		case <-time.After(2 * time.Second):
			t.Fatal("timeout")
		}
	})
}

func newTestService(log *logging.Logger) *Service {
	svc := NewService(log, Config{ContainersBasePath: "./testdata", MinFileSizeBytes: 0, WorkerCount: 1})
	return svc
}

type testAnalyzer struct {
	calls atomic.Int32
}

func (t *testAnalyzer) Analyze(r io.ReaderAt) (*AnalyzerResult, error) {
	t.calls.Add(1)
	return &AnalyzerResult{
		Lang: castpb.Language_LANG_C,
	}, nil
}
