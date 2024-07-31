package ebpftracer

import (
	"context"
	"time"

	"github.com/castai/kvisor/pkg/metrics"
)

// Must be kept in sync with `enum metric` defined in types.h.
type EBPFMetric int

const (
	UnknownMetric EBPFMetric = iota

	NoFreeScratchBuffer
	NoFreeScratchBufferSocketSetState
	NoFreeScratchBufferNetflows
)

func (m EBPFMetric) String() string {
	switch m {
	case NoFreeScratchBuffer:
		return "no_free_scratch_buffer"
	case NoFreeScratchBufferSocketSetState:
		return "no_free_scratch_buffer_socket_set_state"
	case NoFreeScratchBufferNetflows:
		return "no_free_scratch_buffer_netflows"
	default:
		return "unknown"
	}
}

func (t *Tracer) exportEBPFMetricsLoop(ctx context.Context) error {
	exportTimer := time.NewTicker(t.metricExportTimerTickRate)
	defer func() {
		exportTimer.Stop()
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-exportTimer.C:
		}

		iter := t.module.objects.tracerMaps.Metrics.Iterate()
		metric := uint32(0)
		counter := uint64(0)

		for iter.Next(&metric, &counter) {
			metrics.EBPFExposedMetrics.WithLabelValues(EBPFMetric(metric).String()).Set(float64(counter))
		}

		if err := iter.Err(); err != nil {
			t.log.Warnf("got error when trying to export eBPF metrics: %v", err)
		}
	}
}
