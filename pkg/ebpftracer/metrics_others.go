//go:build !linux

package ebpftracer

import (
	"context"

	"github.com/castai/kvisor/pkg/logging"
)

func (t *Tracer) exportMetricsLoop(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		}
	}

}

// On non linux this function is a noop
func EnabledBPFStats(log *logging.Logger) (func(), error) {
	return func() {}, nil
}
