//go:build linux

package ebpftracer

import (
	"context"
	"encoding/base64"
	"errors"

	"github.com/castai/kvisor/cmd/agent/daemon/metrics"
	"github.com/castai/kvisor/pkg/ebpftracer/decoder"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

func (t *Tracer) runPerfBufReaderLoop(ctx context.Context, target *ebpf.Map) error {
	eventsReader, err := ringbuf.NewReader(target)
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		if err := eventsReader.Close(); err != nil {
			t.log.Warnf("closing events reader: %v", err)
		}
	}()

	// Allocate message decoder and perf record once.
	// Under the hood per event reader will reuse and grow raw sample backing bytes slice.
	ebpfMsgDecoder := decoder.NewEventDecoder(t.log, []byte{})
	var record ringbuf.Record

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		err := eventsReader.ReadInto(&record)
		if err != nil {
			if t.cfg.DebugEnabled {
				t.log.Warnf("reading event: %v", err)
			}
			continue
		}

		// Reset decoder with new raw sample bytes.
		ebpfMsgDecoder.Reset(record.RawSample)
		if err := t.decodeAndExportEvent(ctx, ebpfMsgDecoder); err != nil {
			if errors.Is(err, decoder.ErrTooManyArguments) {
				data := ebpfMsgDecoder.Buffer()
				t.log.Errorf("decoding event: too many arguments for event. payload=%s, err=%v",
					base64.StdEncoding.EncodeToString(data), err)
			} else if t.cfg.DebugEnabled || errors.Is(err, ErrPanic) {
				t.log.Errorf("decoding event: %v", err)
			}
			metrics.AgentDecodeEventErrorsTotal.Inc()
			continue
		}
	}
}
