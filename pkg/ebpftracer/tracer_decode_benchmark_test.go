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

func BenchmarkModuleLoad(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		mo := newModule(logging.NewTestLog())
		if err := mo.load(Config{
			BTFPath:                    "/sys/kernel/btf/vmlinux",
			SignalEventsRingBufferSize: 4096,
			EventsRingBufferSize:       4096,
			SkbEventsRingBufferSize:    4096,
			EventsOutputChanSize:       4096,
			DefaultCgroupsVersion:      "",
			DebugEnabled:               false,
			AutomountCgroupv2:          false,
			ContainerClient:            nil,
			CgroupClient:               &MockCgroupClient{},
			SignatureEngine:            nil,
			MountNamespacePIDStore:     nil,
			HomePIDNS:                  0,
			AllowAnyEvent:              false,
			NetflowGrouping:            0,
			TrackSyscallStats:          false,
			ProcessTreeCollector:       nil,
			MetricsReporting:           MetricsReportingConfig{},
			PodName:                    "",
		}); err != nil {
			b.Fatal(err)
		}
		mo.close()
	}
}
