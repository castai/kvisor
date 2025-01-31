//go:build !linux

package ebpftracer

import (
	"context"

	"github.com/cilium/ebpf"
)
func (t *Tracer) runPerfBufReaderLoop(ctx context.Context, target *ebpf.Map) error {
  return nil
}
