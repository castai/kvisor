package ebpftracer

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/castai/logging"
)

func TestTracer(t *testing.T) {
	t.Run("log ebpf issue as warning", func(t *testing.T) {
		r := require.New(t)
		logOut := bytes.NewBuffer(nil)
		log := logging.New(logging.NewTextHandler(logging.TextHandlerConfig{
			Level:  slog.LevelDebug,
			Output: logOut,
		}))
		tr := &Tracer{
			log:                      log,
			currentTracerEbpfMetrics: map[string]uint64{},
			cfg:                      Config{PodName: "pod1"},
		}

		// Log warning on first counter value.
		tr.logInternalEbpfTracerMetric(noFreeScratchBuffer.String(), 1)
		r.Contains(logOut.String(), "ebpf issue, metric=no_free_scratch_buffer value=1 pod=pod1")
		logOut.Reset()

		// Skip log since no new counter value.
		tr.logInternalEbpfTracerMetric(noFreeScratchBuffer.String(), 1)
		r.Len(logOut.String(), 0)

		// Log on new diff.
		tr.logInternalEbpfTracerMetric(noFreeScratchBuffer.String(), 3)
		r.Contains(logOut.String(), "ebpf issue, metric=no_free_scratch_buffer value=2 pod=pod1")
	})
}
