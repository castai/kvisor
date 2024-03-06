package ebpftracer

import (
	"context"
	"os"
	"testing"
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

			tracer := buildTestTracer()

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				err := tracer.decodeAndExportEvent(context.TODO(), data)
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
