package pipeline

import (
	"context"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	kubepb "github.com/castai/kvisor/api/v1/kube"
	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/config"
	"github.com/castai/kvisor/cmd/agent/daemon/enrichment"
	"github.com/castai/kvisor/cmd/agent/daemon/netstats"
	"github.com/castai/kvisor/pkg/cgroup"
	"github.com/castai/kvisor/pkg/containers"
	"github.com/castai/kvisor/pkg/ebpftracer"
	"github.com/castai/kvisor/pkg/ebpftracer/events"
	"github.com/castai/kvisor/pkg/ebpftracer/signature"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/castai/kvisor/pkg/processtree"
	"github.com/samber/lo"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
)

type testAddr struct {
	expected string
	raw      [16]byte
}

func TestController(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Run("container events pipeline", func(t *testing.T) {
		const flushIntervalNever = time.Second * math.MaxInt32
		const batchSizeNever = math.MaxInt

		t.Run("send after batch size is reached with growing containers size", func(t *testing.T) {
			r := require.New(t)
			ctrl := newTestController()
			ctrl.cfg.Events.FlushInterval = 5 * time.Second
			ctrl.cfg.Events.BatchSize = 3
			exporter := &mockContainerEventsSender{}
			ctrl.exporters.ContainerEvents = []ContainerEventsSender{exporter}

			expectedBatchesCount := 100
			go func() {
				for i := range expectedBatchesCount {
					for range 3 {
						ctrl.tracer.(*mockEbpfTracer).eventsChan <- &types.Event{
							Context: &types.EventContext{EventID: events.Write, Ts: 1, CgroupID: uint64(i)},
							Container: &containers.Container{
								PodName: "p" + strconv.Itoa(i),
							},
						}
					}
				}
			}()

			ctrlerr := make(chan error, 1)
			go func() {
				ctrlerr <- ctrl.Run(ctx)
			}()

			r.Eventually(func() bool {
				exporter.mu.Lock()
				defer exporter.mu.Unlock()
				batches := exporter.batches
				fmt.Println(len(batches))
				if len(batches) > expectedBatchesCount {
					t.Fatal("too many batches", len(batches))
				}
				if len(batches) != expectedBatchesCount {
					return false
				}
				return true
			}, 1*time.Second, 10*time.Millisecond)
		})

		t.Run("send after batch size is reached fixed with containers size", func(t *testing.T) {
			r := require.New(t)
			ctrl := newTestController()
			ctrl.cfg.Events.FlushInterval = flushIntervalNever
			ctrl.cfg.Events.BatchSize = 10
			exporter := &mockContainerEventsSender{}
			ctrl.exporters.ContainerEvents = []ContainerEventsSender{exporter}

			go func() {
				for i := range 3 {
					i := i
					go func() {
						for range 100 {
							ctrl.tracer.(*mockEbpfTracer).eventsChan <- &types.Event{
								Context: &types.EventContext{EventID: events.Write, Ts: 1, CgroupID: uint64(i)},
								Container: &containers.Container{
									PodName: "p" + strconv.Itoa(i),
								},
							}
						}
					}()
				}
			}()

			ctrlerr := make(chan error, 1)
			go func() {
				ctrlerr <- ctrl.Run(ctx)
			}()

			r.Eventually(func() bool {
				exporter.mu.Lock()
				defer exporter.mu.Unlock()
				batches := exporter.batches

				if len(batches) == 30 {
					return true
				}

				return false
			}, 1*time.Second, 10*time.Millisecond)
		})

		t.Run("send after flush period", func(t *testing.T) {
			r := require.New(t)
			ctrl := newTestController()
			ctrl.cfg.Events.FlushInterval = 10 * time.Millisecond
			ctrl.cfg.Events.BatchSize = batchSizeNever
			exporter := &mockContainerEventsSender{}
			ctrl.exporters.ContainerEvents = []ContainerEventsSender{exporter}

			ctrl.tracer.(*mockEbpfTracer).eventsChan <- &types.Event{
				Context: &types.EventContext{Ts: 1, CgroupID: 1},
				Container: &containers.Container{
					PodName: "p0",
				},
				Args: types.SchedProcessExecArgs{
					Filepath: "/bin/sh",
					Argv:     []string{"ls"},
				},
			}

			ctrlerr := make(chan error, 1)
			go func() {
				ctrlerr <- ctrl.Run(ctx)
			}()

			r.Eventually(func() bool {
				exporter.mu.Lock()
				defer exporter.mu.Unlock()
				batches := exporter.batches
				if len(batches) > 1 {
					t.Fatal("expected only one batch")
				}
				if len(batches) == 0 {
					return false
				}
				b1 := batches[0].Items[0]
				r.Equal("p0", b1.PodName)
				r.Len(b1.Items, 1)
				r.Equal("/bin/sh", b1.Items[0].GetExec().GetPath())
				r.Equal([]string{"ls"}, b1.Items[0].GetExec().GetArgs())
				return true
			}, 1*time.Second, 10*time.Millisecond)
		})

		t.Run("send after context cancel", func(t *testing.T) {
			r := require.New(t)
			ctrl := newTestController()
			ctrl.cfg.Events.FlushInterval = flushIntervalNever
			ctrl.cfg.Events.BatchSize = batchSizeNever
			exporter := &mockContainerEventsSender{}
			ctrl.exporters.ContainerEvents = []ContainerEventsSender{exporter}

			ctrl.tracer.(*mockEbpfTracer).eventsChan <- &types.Event{
				Context: &types.EventContext{Ts: 1, CgroupID: 1},
				Container: &containers.Container{
					PodName: "p0",
				},
			}

			ctx, cancel := context.WithCancel(context.Background())

			ctrlerr := make(chan error, 1)
			go func() {
				ctrlerr <- ctrl.Run(ctx)
			}()

			r.Eventually(func() bool {
				return len(ctrl.tracer.(*mockEbpfTracer).eventsChan) == 0
			}, 2*time.Second, 10*time.Millisecond)
			cancel()

			r.Eventually(func() bool {
				exporter.mu.Lock()
				defer exporter.mu.Unlock()
				batches := exporter.batches
				if len(batches) > 1 {
					t.Fatal("expected only one batch")
				}
				if len(batches) == 0 {
					return false
				}
				b1 := batches[0].Items[0]
				r.Equal("p0", b1.PodName)
				return true
			}, 1*time.Second, 10*time.Millisecond)
		})

		t.Run("send signature events", func(t *testing.T) {
			r := require.New(t)
			ctrl := newTestController()
			ctrl.cfg.Events.FlushInterval = 10 * time.Millisecond
			ctrl.cfg.Events.BatchSize = batchSizeNever
			exporter := &mockContainerEventsSender{}
			ctrl.exporters.ContainerEvents = []ContainerEventsSender{exporter}
			ctrl.signatureEngine.(*mockSignatureEngine).eventsChan <- signature.Event{
				EbpfEvent: &types.Event{
					Context: &types.EventContext{Ts: 1, CgroupID: 1},
					Container: &containers.Container{
						PodName: "signature",
					},
					Args: types.SchedProcessExecArgs{
						Filepath: "/bin/sh",
						Argv:     []string{"ls"},
					},
				},
				SignatureEvent: &castaipb.SignatureEvent{
					Metadata: &castaipb.SignatureMetadata{
						Version: "v1",
					},
				},
			}

			ctrlerr := make(chan error, 1)
			go func() {
				ctrlerr <- ctrl.Run(ctx)
			}()

			r.Eventually(func() bool {
				exporter.mu.Lock()
				defer exporter.mu.Unlock()
				batches := exporter.batches
				if len(batches) > 1 {
					t.Fatal("expected only one batch")
				}
				if len(batches) == 0 {
					return false
				}
				b1 := batches[0].Items[0]
				r.Equal("signature", b1.PodName)
				r.Equal("v1", b1.Items[0].GetSignature().GetMetadata().Version)
				return true
			}, 1*time.Second, 10*time.Millisecond)
		})

		t.Run("send enriched events", func(t *testing.T) {
			r := require.New(t)
			ctrl := newTestController()
			ctrl.cfg.Events.FlushInterval = 10 * time.Millisecond
			ctrl.cfg.Events.BatchSize = batchSizeNever
			exporter := &mockContainerEventsSender{}
			ctrl.exporters.ContainerEvents = []ContainerEventsSender{exporter}
			ctrl.enrichmentService = &mockEnrichmentService{
				out: make(chan *enrichment.EnrichedContainerEvent, 10),
				enrichFuncs: []func(*enrichment.EnrichedContainerEvent) bool{
					func(e *enrichment.EnrichedContainerEvent) bool {
						if e.EbpfEvent.Context.EventID == events.SchedProcessExec {
							e.Event.GetExec().HashSha256 = []byte("enriched-file-hash")
							return true
						}
						return false
					},
				},
			}
			ctrl.tracer.(*mockEbpfTracer).eventsChan <- &types.Event{
				Context: &types.EventContext{
					EventID:  events.SchedProcessExec,
					Ts:       1,
					CgroupID: 1,
				},
				Container: &containers.Container{
					PodName: "curl",
				},
				Args: types.SchedProcessExecArgs{
					Filepath: "/bin/curl",
					Argv:     []string{"--help"},
				},
			}

			ctrlerr := make(chan error, 1)
			go func() {
				ctrlerr <- ctrl.Run(ctx)
			}()

			r.Eventually(func() bool {
				exporter.mu.Lock()
				defer exporter.mu.Unlock()
				batches := exporter.batches
				if len(batches) > 1 {
					t.Fatal("expected only one batch")
				}
				if len(batches) == 0 {
					return false
				}
				// Should have only one container events batch with one event.
				r.Len(batches[0].Items, 1)
				r.Len(batches[0].Items[0].Items, 1)
				b1 := batches[0].Items[0]
				r.Equal("curl", b1.PodName)
				r.Equal("/bin/curl", b1.Items[0].GetExec().GetPath())
				r.Equal([]string{"--help"}, b1.Items[0].GetExec().GetArgs())
				r.Equal([]byte("enriched-file-hash"), b1.Items[0].GetExec().GetHashSha256())
				return true
			}, 1*time.Second, 50*time.Millisecond)
		})

		t.Run("remove events group on container delete and flush remaining", func(t *testing.T) {
			r := require.New(t)
			ctrl := newTestController()
			exporter := &mockContainerEventsSender{}
			ctrl.exporters.ContainerEvents = []ContainerEventsSender{exporter}
			ctrl.cfg.Events.FlushInterval = flushIntervalNever
			ctrl.cfg.Events.BatchSize = batchSizeNever

			ctrl.tracer.(*mockEbpfTracer).eventsChan <- &types.Event{
				Context: &types.EventContext{Ts: 1, CgroupID: 1},
				Container: &containers.Container{
					PodName: "p999",
				},
			}

			ctrlerr := make(chan error, 1)
			go func() {
				ctrlerr <- ctrl.Run(ctx)
			}()

			// Process initial event and wait for queue drain.
			ctrl.tracer.(*mockEbpfTracer).eventsChan <- &types.Event{
				Context: &types.EventContext{Ts: 1, CgroupID: 1},
				Container: &containers.Container{
					PodName: "p999",
				},
			}
			r.Eventually(func() bool {
				return len(ctrl.tracer.(*mockEbpfTracer).eventsChan) == 0
			}, 2*time.Second, 100*time.Millisecond)

			// Delete container.
			ctrl.onDeleteContainer(&containers.Container{CgroupID: 1})

			// At this point last select from normal priority may be blocked waiting for some even. Trigger to process.
			ctrl.tracer.(*mockEbpfTracer).eventsChan <- &types.Event{
				Context: &types.EventContext{Ts: 1, CgroupID: 2},
				Container: &containers.Container{
					PodName: "p999",
				},
			}

			r.Eventually(func() bool {
				exporter.mu.Lock()
				defer exporter.mu.Unlock()
				batches := exporter.batches
				if len(batches) > 1 {
					t.Fatal("expected only one batch")
				}
				if len(batches) == 0 {
					return false
				}
				r.Len(batches[0].Items, 1)
				r.Equal("p999", batches[0].Items[0].PodName)
				return true
			}, 2*time.Second, 10*time.Millisecond)
		})
	})

	t.Run("container stats pipeline", func(t *testing.T) {
		r := require.New(t)
		ctrl := newTestController()
		exporter := &mockContainerStatsExporter{stats: make(chan *castaipb.StatsBatch)}
		ctrl.exporters.Stats = append(ctrl.exporters.Stats, exporter)
		var nodePSIScrapes int
		ctrl.procHandler = &mockProcHandler{
			psiEnabled: true,
			psiStatsFunc: func(file string) (*castaipb.PSIStats, error) {
				nodePSIScrapes++
				if file == "cpu" {
					if nodePSIScrapes > 1 {
						return &castaipb.PSIStats{
							Some: &castaipb.PSIData{Total: 20},
							Full: nil,
						}, nil
					}
					return &castaipb.PSIStats{
						Some: &castaipb.PSIData{Total: 10},
						Full: nil,
					}, nil
				}
				return &castaipb.PSIStats{}, nil
			},
		}

		ctrl.containersClient.(*mockContainersClient).list = []*containers.Container{
			{
				ID:           "c1",
				Name:         "cont",
				CgroupID:     1,
				PodNamespace: "ns1",
				PodUID:       "p1",
				PodName:      "p1",
				Cgroup:       nil,
			},
		}

		var contStatsScrapes int
		ctrl.containersClient.(*mockContainersClient).getCgroupStatsFunc = func(c *containers.Container) (cgroup.Stats, error) {
			contStatsScrapes++
			if c.CgroupID != 1 {
				return cgroup.Stats{}, cgroup.ErrStatsNotFound
			}
			if contStatsScrapes > 1 {
				return cgroup.Stats{
					CpuStats: &castaipb.CpuStats{
						TotalUsage: 11,
						Psi: &castaipb.PSIStats{
							Some: &castaipb.PSIData{Total: 14},
						},
					},
					MemoryStats: &castaipb.MemoryStats{
						Usage: &castaipb.MemoryData{
							Usage: 20,
						},
					},
				}, nil
			}
			return cgroup.Stats{
				CpuStats: &castaipb.CpuStats{
					TotalUsage: 10,
					Psi: &castaipb.PSIStats{
						Some: &castaipb.PSIData{Total: 12},
					},
				},
				MemoryStats: &castaipb.MemoryStats{
					Usage: &castaipb.MemoryData{
						Usage: 15,
					},
				},
			}, nil
		}

		ctrlerr := make(chan error, 1)
		go func() {
			ctrlerr <- ctrl.Run(ctx)
		}()

		select {
		case e := <-exporter.stats:
			r.Len(e.Items, 2)
			nodeStats, found := lo.Find(e.Items, func(item *castaipb.StatsItem) bool {
				return item.GetNode() != nil
			})
			r.True(found)
			r.Equal(10, int(nodeStats.GetNode().CpuStats.Psi.Some.Total))

			contStats, found := lo.Find(e.Items, func(item *castaipb.StatsItem) bool {
				return item.GetContainer() != nil
			})
			r.True(found)
			// Cpu should return diff between scrapes.
			r.Equal(1, int(contStats.GetContainer().CpuStats.TotalUsage))
			r.Equal(2, int(contStats.GetContainer().CpuStats.Psi.Some.Total))
			// Memory always returns latest value.
			r.Equal(20, int(contStats.GetContainer().MemoryStats.Usage.Usage))

		case err := <-ctrlerr:
			t.Fatal(err)
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for data")
		}
	})

	t.Run("netflow pipeline", func(t *testing.T) {
		t.Run("collect and export netflow", func(t *testing.T) {
			ctrl := newTestController(customizeMockContainersClient(func(t *mockContainersClient) {
				t.list = append(t.list, &containers.Container{
					ID:           "abcd",
					Name:         "container-1",
					CgroupID:     100,
					PodNamespace: "default",
					PodUID:       "abcd",
					PodName:      "test-pod",
					Cgroup: &cgroup.Cgroup{
						Id: 100,
					},
				})
			}))
			exporter := &mockNetflowExporter{events: make(chan *castaipb.Netflow, 10)}
			ctrl.exporters.Netflow = append(ctrl.exporters.Netflow, exporter)

			ctrlerr := make(chan error, 1)
			go func() {
				ctrlerr <- ctrl.Run(ctx)
			}()

			tc := []struct {
				name         string
				family       uint16
				saddr, daddr testAddr
			}{
				{
					name:   "ipv4",
					family: uint16(types.AF_INET),
					saddr: testAddr{
						"10.0.0.10",
						[16]byte{0xa, 0, 0, 0xa},
					},
					daddr: testAddr{
						"172.16.0.10",
						[16]byte{0xac, 0x10, 0, 0xa},
					},
				},
				{
					name:   "ipv6",
					family: uint16(types.AF_INET6),
					saddr: testAddr{
						"fd00::1",
						[16]byte{0xfd, 0x0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1},
					},
					daddr: testAddr{
						"fd01::1",
						[16]byte{0xfd, 0x1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1},
					},
				},
			}

			for _, tt := range tc {
				t.Run(tt.name, func(t *testing.T) {
					r := require.New(t)
					ctrl.tracer.(*mockEbpfTracer).sendNetflowTestEvent(netflowList{
						keys: []ebpftracer.TrafficKey{
							newEbpfTrafficKey(trafficKey{saddr: tt.saddr.raw, daddr: tt.daddr.raw, family: tt.family}),
						},
						vals: []ebpftracer.TrafficSummary{
							{
								TxBytes:   10,
								TxPackets: 5,
								RxBytes:   11,
								RxPackets: 12,
							},
						},
					})
					select {
					case e := <-exporter.events:
						r.Equal(castaipb.NetflowProtocol_NETFLOW_PROTOCOL_TCP, e.Protocol)
						r.Equal(netip.MustParseAddr(tt.saddr.expected).AsSlice(), e.Addr)
						r.Equal(34561, int(e.Port))
						r.Len(e.Destinations, 1)
						dest := e.Destinations[0]
						r.Equal(netip.MustParseAddr(tt.daddr.expected).AsSlice(), dest.Addr)
						r.Equal(80, int(dest.Port))
						r.Equal("test-pod", dest.PodName)
						r.Equal("default", dest.Namespace)
						r.Equal("node1", dest.NodeName)
						r.Equal(int(dest.TxBytes), 10)
						r.Equal(int(dest.TxPackets), 5)
						r.Equal(int(dest.RxBytes), 11)
						r.Equal(int(dest.RxPackets), 12)
					case err := <-ctrlerr:
						t.Fatal(err)
					case <-time.After(time.Second):
						t.Fatal("timed out waiting for data")
					}
				})
			}
		})

		t.Run("aggregate public ips without dns after max limit reached", func(t *testing.T) {
			r := require.New(t)
			ctrl := newTestController(customizeMockContainersClient(func(t *mockContainersClient) {
				t.list = append(t.list, &containers.Container{
					ID:           "abcd",
					Name:         "container-1",
					CgroupID:     100,
					PodNamespace: "default",
					PodUID:       "abcd",
					PodName:      "test-pod",
					Cgroup: &cgroup.Cgroup{
						Id: 100,
					},
				})
			}))
			ctrl.cfg.Netflow.MaxPublicIPs = 1
			exporter := &mockNetflowExporter{events: make(chan *castaipb.Netflow, 10)}
			ctrl.exporters.Netflow = append(ctrl.exporters.Netflow, exporter)

			ctrlerr := make(chan error, 1)
			go func() {
				ctrlerr <- ctrl.Run(ctx)
			}()

			ctrl.tracer.(*mockEbpfTracer).sendNetflowTestEvent(netflowList{
				keys: []ebpftracer.TrafficKey{
					// 10.0.0.10 to private 10.0.0.11, should keep as is
					newEbpfTrafficKey(trafficKey{saddr: [16]byte{0xa, 0, 0, 0xa}, daddr: [16]byte{0xa, 0, 0, 0xb}, family: uint16(types.AF_INET)}),
					// 10.0.0.10 to private 10.0.0.12, should keep as is, private ip destinations are always collected
					newEbpfTrafficKey(trafficKey{saddr: [16]byte{0xa, 0, 0, 0xa}, daddr: [16]byte{0xa, 0, 0, 0xc}, family: uint16(types.AF_INET)}),
					// 10.0.0.10 to public 8.8.8.8, should keep as is, no public ip limit reached yet
					newEbpfTrafficKey(trafficKey{saddr: [16]byte{0xa, 0, 0, 0xa}, daddr: [16]byte{0x8, 0x8, 0x8, 0x8}, family: uint16(types.AF_INET)}),
					// 10.0.0.10 to 1.1.1.1, max public ips count reached, will be aggregated under 0.0.0.0
					newEbpfTrafficKey(trafficKey{saddr: [16]byte{0xa, 0, 0, 0xa}, daddr: [16]byte{0x1, 0x1, 0x1, 0x1}, family: uint16(types.AF_INET)}),
					// 10.0.0.10 to 8.8.8.8, max public ips count reached, will be aggregated under 0.0.0.0
					newEbpfTrafficKey(trafficKey{saddr: [16]byte{0xa, 0, 0, 0xa}, daddr: [16]byte{0x8, 0x8, 0x8, 0x8}, family: uint16(types.AF_INET)}),
				},
				vals: []ebpftracer.TrafficSummary{
					{TxBytes: 1, TxPackets: 1, RxBytes: 1, RxPackets: 1},
					{TxBytes: 1, TxPackets: 2, RxBytes: 1, RxPackets: 1},
					{TxBytes: 1, TxPackets: 1, RxBytes: 1, RxPackets: 1},
					{TxBytes: 3, TxPackets: 3, RxBytes: 3, RxPackets: 3},
					{TxBytes: 4, TxPackets: 5, RxBytes: 6, RxPackets: 7},
				},
			})
			select {
			case e := <-exporter.events:
				r.Equal(castaipb.NetflowProtocol_NETFLOW_PROTOCOL_TCP, e.Protocol)
				r.Len(e.Destinations, 4)
				var actual []string
				slices.SortFunc(e.Destinations, func(e *castaipb.NetflowDestination, e2 *castaipb.NetflowDestination) int {
					return strings.Compare(string(e.Addr), string(e2.Addr))
				})
				for _, d := range e.Destinations {
					actual = append(actual, fmt.Sprintf("%v %v tx_bytes=%d tx_packets=%d rx_bytes=%d rx_packets=%d", e.Addr, d.Addr, d.TxBytes, d.TxPackets, d.RxBytes, d.RxPackets))
				}
				expected := []string{
					"[10 0 0 10] [0 0 0 0] tx_bytes=7 tx_packets=8 rx_bytes=9 rx_packets=10",
					"[10 0 0 10] [8 8 8 8] tx_bytes=1 tx_packets=1 rx_bytes=1 rx_packets=1",
					"[10 0 0 10] [10 0 0 11] tx_bytes=1 tx_packets=1 rx_bytes=1 rx_packets=1",
					"[10 0 0 10] [10 0 0 12] tx_bytes=1 tx_packets=2 rx_bytes=1 rx_packets=1",
				}
				for i := range expected {
					r.Equal(expected[i], actual[i])
				}
			case err := <-ctrlerr:
				t.Fatal(err)
			case <-time.After(time.Second):
				t.Fatal("timed out waiting for data")
			}
		})
	})
}

func (m *mockEbpfTracer) sendNetflowTestEvent(v netflowList) {
	m.netflowCollectChan <- v
}

type trafficKey struct {
	family uint16
	saddr  [16]uint8
	daddr  [16]uint8
}

func newEbpfTrafficKey(k trafficKey) ebpftracer.TrafficKey {
	return ebpftracer.TrafficKey{
		ProcessIdentity: struct {
			Pid          uint32
			PidStartTime uint64
			CgroupId     uint64
			Comm         [16]uint8
		}{
			Pid:          1,
			PidStartTime: 0,
			CgroupId:     100,
			Comm:         [16]uint8{},
		},
		Tuple: struct {
			Saddr  struct{ Raw [16]uint8 }
			Daddr  struct{ Raw [16]uint8 }
			Sport  uint16
			Dport  uint16
			Family uint16
		}{
			Saddr:  struct{ Raw [16]uint8 }{Raw: k.saddr},
			Daddr:  struct{ Raw [16]uint8 }{Raw: k.daddr},
			Sport:  34561,
			Dport:  80,
			Family: k.family,
		},
		Proto: unix.IPPROTO_TCP,
	}
}

type customizeMockTracer func(t *mockEbpfTracer)
type customizeMockContainersClient func(t *mockContainersClient)

func newTestController(opts ...any) *Controller {
	log := logging.NewTestLog()
	cfg := Config{
		Stats: config.StatsConfig{
			Enabled:        false,
			ScrapeInterval: time.Millisecond,
		},
		Netflow: config.NetflowConfig{
			ExportInterval: time.Millisecond,
		},
	}
	exporters := NewExporters(log)
	contClient := &mockContainersClient{}
	contClientCustomizer := getOptOr[customizeMockContainersClient](opts, func(t *mockContainersClient) {})
	contClientCustomizer(contClient)

	netReader := &mockNetStatsReader{}
	ctClient := &mockConntrackClient{}

	tracer := &mockEbpfTracer{
		eventsChan:         make(chan *types.Event, 500),
		netflowCollectChan: make(chan netflowList, 100),
	}
	tracerCustomizer := getOptOr[customizeMockTracer](opts, func(t *mockEbpfTracer) {})
	tracerCustomizer(tracer)

	sigEngine := &mockSignatureEngine{eventsChan: make(chan signature.Event, 100)}
	enrichService := &mockEnrichmentService{}
	kubeClient := &mockKubeClient{}
	processTreeCollector := &mockProcessTreeController{}

	procHandler := &mockProcHandler{}

	ctrl := NewController(
		log,
		cfg,
		exporters,
		contClient,
		netReader,
		ctClient,
		tracer,
		sigEngine,
		kubeClient,
		processTreeCollector,
		procHandler,
		enrichService,
	)
	return ctrl
}

type mockContainerEventsSender struct {
	batches []*castaipb.ContainerEventsBatch
	mu      sync.Mutex
}

func (m *mockContainerEventsSender) Send(ctx context.Context, batch *castaipb.ContainerEventsBatch) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Add deep copy because we cleanup batch items after it's sent.
	pbBytes, err := protojson.Marshal(batch)
	if err != nil {
		return err
	}
	var res castaipb.ContainerEventsBatch
	if err := protojson.Unmarshal(pbBytes, &res); err != nil {
		return err
	}
	m.batches = append(m.batches, &res)
	return nil
}

type mockNetflowExporter struct {
	events chan *castaipb.Netflow
}

func (m *mockNetflowExporter) Run(ctx context.Context) error {
	return nil
}

func (m *mockNetflowExporter) Enqueue(e *castaipb.Netflow) {
	m.events <- e
}

type mockContainersClient struct {
	list               []*containers.Container
	getCgroupStatsFunc func(c *containers.Container) (cgroup.Stats, error)
}

func (m *mockContainersClient) GetCgroupStats(c *containers.Container) (cgroup.Stats, error) {
	if m.getCgroupStatsFunc != nil {
		return m.getCgroupStatsFunc(c)
	}
	return cgroup.Stats{}, nil
}

func (m *mockContainersClient) ListContainers(filter func(c *containers.Container) bool) []*containers.Container {
	return m.list
}

func (m *mockContainersClient) GetOrLoadContainerByCgroupID(ctx context.Context, cgroup uint64) (*containers.Container, error) {
	for _, v := range m.list {
		if v.CgroupID == cgroup {
			return v, nil
		}
	}
	return nil, containers.ErrContainerNotFound
}

func (m *mockContainersClient) LookupContainerForCgroupInCache(cgroup uint64) (*containers.Container, bool, error) {
	for _, v := range m.list {
		if v.CgroupID == cgroup {
			return v, true, nil
		}
	}
	return nil, false, containers.ErrContainerNotFound
}

func (m *mockContainersClient) CleanupCgroup(cgroup cgroup.ID) {
	return
}

func (m *mockContainersClient) GetCgroupsInNamespace(namespace string) []uint64 {
	return []uint64{}
}

func (m *mockContainersClient) RegisterContainerCreatedListener(l containers.ContainerCreatedListener) {
	return
}

func (m *mockContainersClient) RegisterContainerDeletedListener(l containers.ContainerDeletedListener) {
	return
}

type mockNetStatsReader struct {
}

func (m *mockNetStatsReader) Read(pid uint32) ([]netstats.InterfaceStats, error) {
	return nil, nil
}

type mockConntrackClient struct {
}

func (m *mockConntrackClient) GetDestination(src, dst netip.AddrPort) (netip.AddrPort, bool) {
	return netip.AddrPort{}, false
}

var _ ebpfTracer = (*mockEbpfTracer)(nil)

type mockEbpfTracer struct {
	eventsChan         chan *types.Event
	syscallStats       map[ebpftracer.SyscallStatsKeyCgroupID][]ebpftracer.SyscallStats
	netflowCollectChan chan netflowList
}

func (m *mockEbpfTracer) GetEventName(id events.ID) string {
	return strconv.Itoa(int(id))
}

type netflowList struct {
	keys []ebpftracer.TrafficKey
	vals []ebpftracer.TrafficSummary
}

func (m *mockEbpfTracer) CollectNetworkSummary() ([]ebpftracer.TrafficKey, []ebpftracer.TrafficSummary, error) {
	select {
	case v := <-m.netflowCollectChan:
		return v.keys, v.vals, nil
	default:
		return nil, nil, nil
	}
}

func (m *mockEbpfTracer) ReadSyscallStats() (map[ebpftracer.SyscallStatsKeyCgroupID][]ebpftracer.SyscallStats, error) {
	// Inc stats each time scrape is called since we export only stats which changed.
	for _, s := range m.syscallStats {
		for i := range s {
			s[i].Count++
		}
	}
	return m.syscallStats, nil
}

func (m *mockEbpfTracer) Events() <-chan *types.Event {
	return m.eventsChan
}

func (m *mockEbpfTracer) MuteEventsFromCgroup(cgroup uint64, reason string) error {
	return nil
}

func (m *mockEbpfTracer) MuteEventsFromCgroups(cgroups []uint64, reason string) error {
	return nil
}

func (m *mockEbpfTracer) UnmuteEventsFromCgroup(cgroup uint64) error {
	return nil
}

func (m *mockEbpfTracer) UnmuteEventsFromCgroups(cgroups []uint64) error {
	return nil
}

func (m *mockEbpfTracer) IsCgroupMuted(cgroup uint64) bool {
	return true
}

type mockSignatureEngine struct {
	eventsChan chan signature.Event
}

func (m *mockSignatureEngine) Events() <-chan signature.Event {
	return m.eventsChan
}

type mockEnrichmentService struct {
	out         chan *enrichment.EnrichedContainerEvent
	enrichFuncs []func(*enrichment.EnrichedContainerEvent) bool
}

func (m *mockEnrichmentService) Enqueue(e *enrichment.EnrichedContainerEvent) bool {
	if m.out == nil {
		return false
	}

	var enriched bool
	for _, enrichFunc := range m.enrichFuncs {
		if enrichFunc(e) {
			enriched = true
			m.out <- e
		}
	}
	return enriched
}

func (m *mockEnrichmentService) Events() <-chan *enrichment.EnrichedContainerEvent {
	return m.out
}

type mockKubeClient struct {
}

func (m *mockKubeClient) GetClusterInfo(ctx context.Context, in *kubepb.GetClusterInfoRequest, opts ...grpc.CallOption) (*kubepb.GetClusterInfoResponse, error) {
	return &kubepb.GetClusterInfoResponse{
		PodsCidr:    []string{"10.0.0.0/16", "fd00::/48"},
		ServiceCidr: []string{"172.16.0.0/16", "fd01::/48"},
	}, nil
}

func (m *mockKubeClient) GetIPInfo(ctx context.Context, in *kubepb.GetIPInfoRequest, opts ...grpc.CallOption) (*kubepb.GetIPInfoResponse, error) {
	return &kubepb.GetIPInfoResponse{
		Info: &kubepb.IPInfo{
			PodUid:       "abcd",
			PodName:      "test-pod",
			Namespace:    "default",
			WorkloadName: "test-pod",
			WorkloadKind: "Deployment",
			WorkloadUid:  "abcd",
			Zone:         "us-east-1a",
			NodeName:     "node1",
		},
	}, nil
}

func (m *mockKubeClient) GetPod(ctx context.Context, in *kubepb.GetPodRequest, opts ...grpc.CallOption) (*kubepb.GetPodResponse, error) {
	return &kubepb.GetPodResponse{
		Pod: &kubepb.Pod{},
	}, nil
}

type mockProcessTreeController struct {
	eventsChan chan processtree.ProcessTreeEvent
}

func (m *mockProcessTreeController) Events() <-chan processtree.ProcessTreeEvent {
	return m.eventsChan
}

func getOptOr[T any](opts []any, or T) T {
	for _, opt := range opts {
		switch v := opt.(type) {
		case T:
			return v
		}
	}

	return or
}

type mockProcHandler struct {
	psiEnabled   bool
	psiStatsFunc func(file string) (*castaipb.PSIStats, error)
}

func (m mockProcHandler) PSIEnabled() bool {
	return true
}

func (m mockProcHandler) GetPSIStats(file string) (*castaipb.PSIStats, error) {
	if m.psiStatsFunc != nil {
		return m.psiStatsFunc(file)
	}
	return &castaipb.PSIStats{}, nil
}

func (m mockProcHandler) GetMeminfoStats() (*castaipb.MemoryStats, error) {
	return &castaipb.MemoryStats{}, nil
}

type mockContainerStatsExporter struct {
	stats chan *castaipb.StatsBatch
}

func (m *mockContainerStatsExporter) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (m *mockContainerStatsExporter) Enqueue(e *castaipb.StatsBatch) {
	m.stats <- e
}
