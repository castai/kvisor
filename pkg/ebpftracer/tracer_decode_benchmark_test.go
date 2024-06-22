package ebpftracer

import (
	"context"
	"os"
	"testing"

	"github.com/castai/kvisor/pkg/ebpftracer/decoder"
	"github.com/castai/kvisor/pkg/logging"
)

func BenchmarkFilterDecodeAndExportEvent(b *testing.B) {
	files, err := os.ReadDir("./sample_events")
	if err != nil {
		b.Fatal(err)
	}

	for _, f := range files {
		b.Run(f.Name(), func(b *testing.B) {
			data, err := os.ReadFile("./sample_events/" + f.Name())
			if err != nil {
				b.Fatal(err)
			}
			dec := decoder.NewEventDecoder(logging.NewTestLog(), []byte{})

			tracer := buildTestTracer()

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				dec.Reset(data)
				err := tracer.decodeAndExportEvent(context.TODO(), dec)
				if err != nil {
					b.Fatal(err)
				}

				select {
				case <-tracer.eventsChan:
				default:
					b.Fatal()
				}
			}
		})
	}
}
