package pipeline

import (
	"context"
	"fmt"
	"math"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shirou/gopsutil/v4/disk"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	kubepb "github.com/castai/kvisor/api/v1/kube"
	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/config"
	"github.com/castai/kvisor/cmd/agent/daemon/enrichment"
	"github.com/castai/kvisor/cmd/agent/daemon/export"
	"github.com/castai/kvisor/cmd/agent/daemon/netstats"
	"github.com/castai/kvisor/pkg/cgroup"
	"github.com/castai/kvisor/pkg/containers"
	"github.com/castai/kvisor/pkg/ebpftracer"
	"github.com/castai/kvisor/pkg/ebpftracer/events"
	"github.com/castai/kvisor/pkg/ebpftracer/signature"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/castai/kvisor/pkg/processtree"
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

		t.Run("enqueue after batch size is reached", func(t *testing.T) {
			r := require.New(t)
			ctrl := newTestController()
			ctrl.cfg.Events.Enabled = true
			ctrl.cfg.DataBatch.FlushInterval = flushIntervalNever
			ctrl.cfg.DataBatch.MaxBatchSizeBytes = 4096

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

			exp := getTestDataBatchExporter(ctrl)

			r.Eventually(func() bool {
				batches := exp.getEvents()

				if len(batches) > 0 {
					return true
				}

				return false
			}, 1*time.Second, 10*time.Millisecond)
		})

		t.Run("enqueue after flush period", func(t *testing.T) {
			r := require.New(t)
			ctrl := newTestController()
			ctrl.cfg.Events.Enabled = true
			ctrl.cfg.DataBatch.FlushInterval = 10 * time.Millisecond
			ctrl.cfg.DataBatch.MaxBatchSizeBytes = batchSizeNever

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

			exp := getTestDataBatchExporter(ctrl)

			r.Eventually(func() bool {
				batches := exp.getEvents()
				if len(batches) > 1 {
					t.Fatal("expected only one batch")
				}
				if len(batches) == 0 {
					return false
				}
				b1 := batches[0]
				r.Equal("p0", b1.PodName)
				r.Len(b1.Items, 1)
				r.Equal("/bin/sh", b1.Items[0].GetExec().GetPath())
				r.Equal([]string{"ls"}, b1.Items[0].GetExec().GetArgs())
				return true
			}, 1*time.Second, 10*time.Millisecond)
		})

		t.Run("enqueue after context cancel", func(t *testing.T) {
			r := require.New(t)
			ctrl := newTestController()
			ctrl.cfg.Events.Enabled = true
			ctrl.cfg.DataBatch.FlushInterval = flushIntervalNever
			ctrl.cfg.DataBatch.MaxBatchSizeBytes = 1

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

			exp := getTestDataBatchExporter(ctrl)

			r.Eventually(func() bool {
				batches := exp.getEvents()
				if len(batches) > 1 {
					t.Fatal("expected only one batch")
				}
				if len(batches) == 0 {
					return false
				}
				b1 := batches[0]
				r.Equal("p0", b1.PodName)
				return true
			}, 1*time.Second, 10*time.Millisecond)
		})

		t.Run("enqueue signature events", func(t *testing.T) {
			r := require.New(t)
			ctrl := newTestController()
			ctrl.cfg.Events.Enabled = true
			ctrl.cfg.DataBatch.FlushInterval = 10 * time.Millisecond
			ctrl.cfg.DataBatch.MaxBatchSizeBytes = batchSizeNever
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

			exp := getTestDataBatchExporter(ctrl)

			r.Eventually(func() bool {
				batches := exp.getEvents()
				if len(batches) > 1 {
					t.Fatal("expected only one batch")
				}
				if len(batches) == 0 {
					return false
				}
				b1 := batches[0]
				r.Equal("signature", b1.PodName)
				r.Equal("v1", b1.Items[0].GetSignature().GetMetadata().Version)
				return true
			}, 1*time.Second, 10*time.Millisecond)
		})

		t.Run("enqueue enriched events", func(t *testing.T) {
			r := require.New(t)
			ctrl := newTestController()
			ctrl.cfg.Events.Enabled = true
			ctrl.cfg.DataBatch.FlushInterval = 10 * time.Millisecond
			ctrl.cfg.DataBatch.MaxBatchSizeBytes = batchSizeNever
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

			exp := getTestDataBatchExporter(ctrl)

			r.Eventually(func() bool {
				batches := exp.getEvents()
				if len(batches) > 1 {
					t.Fatal("expected only one batch")
				}
				if len(batches) == 0 {
					return false
				}
				// Should have only one container events batch with one event.
				r.Len(batches[0].Items, 1)
				b1 := batches[0]
				r.Equal("curl", b1.PodName)
				r.Equal("/bin/curl", b1.Items[0].GetExec().GetPath())
				r.Equal([]string{"--help"}, b1.Items[0].GetExec().GetArgs())
				r.Equal([]byte("enriched-file-hash"), b1.Items[0].GetExec().GetHashSha256())
				return true
			}, 1*time.Second, 50*time.Millisecond)
		})

		t.Run("reset event groups items after export", func(t *testing.T) {
			r := require.New(t)
			ctrl := newTestController()
			ctrl.cfg.Events.Enabled = true
			ctrl.cfg.DataBatch.FlushInterval = flushIntervalNever
			ctrl.cfg.DataBatch.MaxBatchSizeBytes = 1

			go func() {
				for i := range 3 {
					i := i
					time.Sleep(100 * time.Millisecond)
					ctrl.tracer.(*mockEbpfTracer).eventsChan <- &types.Event{
						Context: &types.EventContext{Ts: 1, CgroupID: 1},
						Container: &containers.Container{
							PodName: "p0",
						},
						Args: types.SchedProcessExecArgs{
							Filepath: fmt.Sprintf("/bin/sh/%d", i),
						},
					}
				}
			}()

			ctrlerr := make(chan error, 1)
			go func() {
				ctrlerr <- ctrl.Run(ctx)
			}()

			exp := getTestDataBatchExporter(ctrl)

			errc := make(chan error, 1)
			receivedFilePaths := make(chan []string, 1)
			go func() {
				for {
					batches := exp.getEvents()
					if len(batches) == 0 {
						continue
					}
					var filePaths []string
					for _, b := range batches {
						for _, item := range b.Items {
							filePaths = append(filePaths, item.GetExec().GetPath())
							if len(filePaths) == 3 {
								receivedFilePaths <- filePaths
								return
							}
						}
					}
				}
			}()

			select {
			case filePaths := <-receivedFilePaths:
				r.Equal([]string{"/bin/sh/0", "/bin/sh/1", "/bin/sh/2"}, filePaths)
			case err := <-errc:
				t.Fatal(err)
			case <-time.After(1 * time.Second):
				t.Fatal("timeout")
			}
		})

		t.Run("remove not active events group after send", func(t *testing.T) {
			r := require.New(t)
			ctrl := newTestController()
			ctrl.cfg.Events.Enabled = true
			ctrl.cfg.DataBatch.FlushInterval = flushIntervalNever
			ctrl.cfg.DataBatch.MaxBatchSizeBytes = 1
			ctx, cancel := context.WithCancel(ctx)

			ctrl.tracer.(*mockEbpfTracer).eventsChan <- &types.Event{
				Context: &types.EventContext{Ts: 1, CgroupID: 1},
				Container: &containers.Container{
					PodName: "p999",
				},
			}

			ctrl.eventGroups[2] = &containerEventsGroup{
				updatedAt: time.Now().Add(-time.Hour),
				pb:        &castaipb.ContainerEvents{},
			}

			ctrlerr := make(chan error, 1)
			go func() {
				ctrlerr <- ctrl.Run(ctx)
			}()

			exp := getTestDataBatchExporter(ctrl)

			r.Eventually(func() bool {
				batch := exp.getEvents()
				if len(batch) == 0 {
					return false
				}
				cancel()
				<-ctrlerr
				r.Equal("p999", batch[0].PodName)
				r.Len(ctrl.eventGroups, 1)
				r.NotNil(ctrl.eventGroups[1])
				return true
			}, 2*time.Second, 10*time.Millisecond)
		})
	})

	t.Run("stats pipeline", func(t *testing.T) {
		t.Run("collect cgroup stats", func(t *testing.T) {
			r := require.New(t)
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			ctrl := newTestController()
			ctrl.cfg.Stats.Enabled = true
			ctrl.procHandler = &mockProcHandler{
				psiEnabled: false,
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

			var contCpuUsage uint64 = 3_000_000_000
			var contCpuPSI uint64 = 1_000_000_000
			ctrl.containersClient.(*mockContainersClient).getCgroupStatsFunc = func(c *containers.Container) (cgroup.Stats, error) {
				if c.CgroupID != 1 {
					return cgroup.Stats{}, cgroup.ErrStatsNotFound
				}
				contCpuUsage += 1_000
				contCpuPSI += 2_000
				return cgroup.Stats{
					CpuStats: &castaipb.CpuStats{
						TotalUsage: contCpuUsage,
						Psi: &castaipb.PSIStats{
							Some: &castaipb.PSIData{Total: contCpuPSI},
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

			exp := getTestDataBatchExporter(ctrl)

			r.Eventually(func() bool {
				// Wait for at least 10 different scrapes.
				if len(exp.getContainerStats()) < 10 {
					return false
				}

				contStats := exp.getContainerStats()
				// Cpu should return diff between scrapes.
				r.Equal(1_000, int(contStats[9].CpuStats.TotalUsage))
				r.Equal(2_000, int(contStats[9].CpuStats.Psi.Some.Total))
				// Memory always returns latest value.
				r.Equal(15, int(contStats[9].MemoryStats.Usage.Usage))

				return true
			}, 1*time.Second, 1*time.Millisecond)
		})

		t.Run("collect file access stats", func(t *testing.T) {
			r := require.New(t)
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			ctrl := newTestController()
			ctrl.cfg.Stats.FileAccessEnabled = true
			ctrl.procHandler = &mockProcHandler{
				psiEnabled: false,
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

			ctrl.tracer.(*mockEbpfTracer).collectFileAccessStatsFunc = func() ([]ebpftracer.FileAccessKey, []ebpftracer.FileAccessStats, error) {
				return []ebpftracer.FileAccessKey{
						{
							CgroupId: 1,
							Inode:    10,
							Dev:      1,
						},
					}, []ebpftracer.FileAccessStats{
						{
							Reads:    101,
							Filepath: [256]byte{'/', 'u', 's', 'r'},
						},
					}, nil
			}

			ctrlerr := make(chan error, 1)
			go func() {
				ctrlerr <- ctrl.Run(ctx)
			}()

			exp := getTestDataBatchExporter(ctrl)

			r.Eventually(func() bool {
				if len(exp.getContainerStats()) < 1 {
					return false
				}

				contStats := exp.getContainerStats()
				r.NotNil(contStats[0].FilesAccessStats)
				r.Equal([]uint32{101}, contStats[0].FilesAccessStats.Reads)
				r.Equal([]string{"/usr"}, contStats[0].FilesAccessStats.Paths)

				return true
			}, 1*time.Second, 1*time.Millisecond)
		})

		t.Run("collect node stats", func(t *testing.T) {
			r := require.New(t)
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			ctrl := newTestController()
			ctrl.cfg.Stats.Enabled = true
			var nodeCpuPSIUsage uint64 = 1_000_000_000
			ctrl.procHandler = &mockProcHandler{
				psiEnabled: true,
				psiStatsFunc: func(file string) (*castaipb.PSIStats, error) {
					if file == "cpu" {
						nodeCpuPSIUsage += 1_000
						return &castaipb.PSIStats{
							Some: &castaipb.PSIData{Total: nodeCpuPSIUsage},
							Full: nil,
						}, nil
					}
					return &castaipb.PSIStats{}, nil
				},
			}

			ctrlerr := make(chan error, 1)
			go func() {
				ctrlerr <- ctrl.Run(ctx)
			}()

			exp := getTestDataBatchExporter(ctrl)

			r.Eventually(func() bool {
				nodeStats := exp.getNodeStats()
				if len(nodeStats) < 10 {
					return false
				}
				r.Equal(1_000, int(nodeStats[9].CpuStats.Psi.Some.Total))

				return true
			}, 1*time.Second, 1*time.Millisecond)
		})
	})

	t.Run("netflow pipeline", func(t *testing.T) {
		t.Run("collect and export netflow", func(t *testing.T) {
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
					ctrl.cfg.Netflow.Enabled = true

					ctrl.tracer.(*mockEbpfTracer).collectNetworkSummaryFunc = func() ([]ebpftracer.TrafficKey, []ebpftracer.TrafficSummary, error) {
						return []ebpftracer.TrafficKey{
								newEbpfTrafficKey(trafficKey{saddr: tt.saddr.raw, daddr: tt.daddr.raw, family: tt.family}),
							}, []ebpftracer.TrafficSummary{
								{
									TxBytes:   10,
									TxPackets: 5,
									RxBytes:   11,
									RxPackets: 12,
								},
							}, nil
					}

					ctrlerr := make(chan error, 1)
					go func() {
						ctrlerr <- ctrl.Run(ctx)
					}()

					exp := getTestDataBatchExporter(ctrl)

					r.Eventually(func() bool {
						flows := exp.getNetflows()
						if len(flows) == 0 {
							return false
						}
						e := flows[0]
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
						return true
					}, 3*time.Second, 1*time.Millisecond)
				})
			}
		})

		t.Run("group flows by container and process", func(t *testing.T) {
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
			ctrl.cfg.Netflow.Enabled = true

			key1 := newEbpfTrafficKey(trafficKey{saddr: [16]byte{0xa, 0, 0, 0xa}, daddr: [16]byte{0xa, 0, 1, 0xa}, family: uint16(types.AF_INET)})
			key1.ProcessIdentity.CgroupId = 100
			key1.ProcessIdentity.Pid = 1
			key1.ProcessIdentity.PidStartTime = 1
			val1 := ebpftracer.TrafficSummary{
				TxBytes:   10,
				TxPackets: 5,
				RxBytes:   11,
				RxPackets: 12,
			}

			key2 := newEbpfTrafficKey(trafficKey{saddr: [16]byte{0xa, 0, 0, 0xa}, daddr: [16]byte{0xa, 0, 1, 0xa}, family: uint16(types.AF_INET)})
			key2.ProcessIdentity.CgroupId = 100
			key2.ProcessIdentity.Pid = 2
			key2.ProcessIdentity.PidStartTime = 2
			val2 := ebpftracer.TrafficSummary{
				TxBytes:   11,
				TxPackets: 6,
				RxBytes:   12,
				RxPackets: 13,
			}

			ctrl.tracer.(*mockEbpfTracer).collectNetworkSummaryFunc = func() ([]ebpftracer.TrafficKey, []ebpftracer.TrafficSummary, error) {
				return []ebpftracer.TrafficKey{
						key1, key2,
					}, []ebpftracer.TrafficSummary{
						val1, val2,
					}, nil
			}

			ctrlerr := make(chan error, 1)
			go func() {
				ctrlerr <- ctrl.Run(ctx)
			}()

			exp := getTestDataBatchExporter(ctrl)

			r.Eventually(func() bool {
				flows := exp.getNetflows()
				if len(flows) == 0 {
					return false
				}
				f1 := flows[0]
				f2 := flows[1]
				r.Equal("container-1", f1.ContainerName)
				r.Equal(f1.ContainerName, f2.ContainerName)
				r.NotEqual(f1.Pid, f2.Pid)
				return true
			}, 3*time.Second, 1*time.Millisecond)
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
			ctrl.cfg.Netflow.Enabled = true
			ctrl.cfg.Netflow.MaxPublicIPs = 1

			ctrl.tracer.(*mockEbpfTracer).collectNetworkSummaryFunc = func() ([]ebpftracer.TrafficKey, []ebpftracer.TrafficSummary, error) {
				return []ebpftracer.TrafficKey{
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
					}, []ebpftracer.TrafficSummary{
						{TxBytes: 1, TxPackets: 1, RxBytes: 1, RxPackets: 1},
						{TxBytes: 1, TxPackets: 2, RxBytes: 1, RxPackets: 1},
						{TxBytes: 1, TxPackets: 1, RxBytes: 1, RxPackets: 1},
						{TxBytes: 3, TxPackets: 3, RxBytes: 3, RxPackets: 3},
						{TxBytes: 4, TxPackets: 5, RxBytes: 6, RxPackets: 7},
					}, nil
			}

			ctrlerr := make(chan error, 1)
			go func() {
				ctrlerr <- ctrl.Run(ctx)
			}()

			exp := getTestDataBatchExporter(ctrl)
			r.Eventually(func() bool {
				flows := exp.getNetflows()
				if len(flows) == 0 {
					return false
				}
				e := flows[0]
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
				return true
			}, 3*time.Second, 1*time.Millisecond)

		})
	})
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
		}{
			Pid:          1,
			PidStartTime: 0,
			CgroupId:     100,
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
			Enabled:        false,
			ExportInterval: time.Millisecond,
		},
		Events: config.EventsConfig{
			Enabled: false,
		},
		DataBatch: config.DataBatchConfig{
			MaxBatchSizeBytes: 1 << 20,
			FlushInterval:     time.Millisecond,
			ExportTimeout:     2 * time.Millisecond,
		},
	}
	exporters := []export.DataBatchWriter{newMockDataBatchExporter()}
	contClient := &mockContainersClient{}
	contClientCustomizer := getOptOr[customizeMockContainersClient](opts, func(t *mockContainersClient) {})
	contClientCustomizer(contClient)

	netReader := &mockNetStatsReader{}
	ctClient := &mockConntrackClient{}

	tracer := &mockEbpfTracer{
		eventsChan: make(chan *types.Event, 500),
	}
	tracerCustomizer := getOptOr[customizeMockTracer](opts, func(t *mockEbpfTracer) {})
	tracerCustomizer(tracer)

	sigEngine := &mockSignatureEngine{eventsChan: make(chan signature.Event, 100)}
	enrichService := &mockEnrichmentService{}
	kubeClient := &mockKubeClient{}
	processTreeCollector := &mockProcessTreeController{}

	procHandler := &mockProcHandler{}
	//metricsClient := &mockMetricClient{}
	blockDeviceMetrics := &mockBlockDeviceMetricsWriter{}
	filesystemMetrics := &mockFilesystemMetricsWriter{}

	diskStatsProvider := &mockDiskStatsProvider{}
	
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
		blockDeviceMetrics,
		filesystemMetrics,
		diskStatsProvider,
	)
	return ctrl
}

func getTestDataBatchExporter(ctrl *Controller) *mockDataBatchExporter {
	exp := ctrl.exporters[0]
	return exp.(*mockDataBatchExporter)
}

func newMockDataBatchExporter() *mockDataBatchExporter {
	return &mockDataBatchExporter{}
}

type mockDataBatchExporter struct {
	mu    sync.Mutex
	items []*castaipb.DataBatchItem
}

func (m *mockDataBatchExporter) Write(ctx context.Context, req *castaipb.WriteDataBatchRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Add deep copy because we cleanup batch items after it's sent.
	pbBytes, err := protojson.Marshal(req)
	if err != nil {
		return err
	}
	var res castaipb.WriteDataBatchRequest
	if err := protojson.Unmarshal(pbBytes, &res); err != nil {
		return err
	}
	m.items = append(m.items, res.Items...)
	return nil
}

func (m *mockDataBatchExporter) Name() string {
	return "test"
}

func (m *mockDataBatchExporter) getEvents() []*castaipb.ContainerEvents {
	m.mu.Lock()
	defer m.mu.Unlock()
	var res []*castaipb.ContainerEvents
	for _, item := range m.items {
		if v := item.GetContainerEvents(); v != nil {
			res = append(res, deepProtoCopy(v))
		}
	}
	return res
}

func (m *mockDataBatchExporter) getNetflows() []*castaipb.Netflow {
	m.mu.Lock()
	defer m.mu.Unlock()
	var res []*castaipb.Netflow
	for _, item := range m.items {
		if v := item.GetNetflow(); v != nil {
			res = append(res, deepProtoCopy(v))
		}
	}
	return res
}

func (m *mockDataBatchExporter) getContainerStats() []*castaipb.ContainerStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	var res []*castaipb.ContainerStats
	for _, item := range m.items {
		if v := item.GetContainerStats(); v != nil {
			res = append(res, deepProtoCopy(v))
		}
	}
	return res
}

func (m *mockDataBatchExporter) getNodeStats() []*castaipb.NodeStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	var res []*castaipb.NodeStats
	for _, item := range m.items {
		if v := item.GetNodeStats(); v != nil {
			res = append(res, deepProtoCopy(v))
		}
	}
	return res
}

// deepProtoCopy is used to copy proto messages to avoid race conditions it tests.
func deepProtoCopy[T proto.Message](in T) T {
	data, err := protojson.Marshal(in)
	if err != nil {
		panic(err)
	}
	out := reflect.New(reflect.TypeOf(in).Elem()).Interface().(proto.Message)
	if err := protojson.Unmarshal(data, out); err != nil {
		panic(err)
	}
	return out.(T)
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

func (m *mockContainersClient) CleanupByCgroupID(cgroup cgroup.ID) {
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
	eventsChan                 chan *types.Event
	syscallStats               map[ebpftracer.SyscallStatsKeyCgroupID][]ebpftracer.SyscallStats
	collectNetworkSummaryFunc  func() ([]ebpftracer.TrafficKey, []ebpftracer.TrafficSummary, error)
	collectFileAccessStatsFunc func() ([]ebpftracer.FileAccessKey, []ebpftracer.FileAccessStats, error)
}

func (m *mockEbpfTracer) GetEventName(id events.ID) string {
	return strconv.Itoa(int(id))
}

type netflowList struct {
	keys []ebpftracer.TrafficKey
	vals []ebpftracer.TrafficSummary
}

func (m *mockEbpfTracer) CollectNetworkSummary() ([]ebpftracer.TrafficKey, []ebpftracer.TrafficSummary, error) {
	if m.collectNetworkSummaryFunc != nil {
		return m.collectNetworkSummaryFunc()
	}
	return nil, nil, nil
}

func (m *mockEbpfTracer) CollectFileAccessStats() ([]ebpftracer.FileAccessKey, []ebpftracer.FileAccessStats, error) {
	if m.collectFileAccessStatsFunc != nil {
		return m.collectFileAccessStatsFunc()
	}
	return nil, nil, nil
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
}

func (m *mockProcessTreeController) GetCurrentProcesses(ctx context.Context) ([]processtree.ProcessEvent, error) {
	return []processtree.ProcessEvent{}, nil
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

type mockMetricClient struct{}

func (m *mockMetricClient) NewMetric(name string, options ...interface{}) (interface{}, error) {
	return nil, nil
}

func (m *mockMetricClient) Start(ctx context.Context) error {
	return nil
}

func (m *mockMetricClient) Stop() error {
	return nil
}

func (m *mockMetricClient) Add(name string, metric interface{}) error {
	return nil
}

type mockBlockDeviceMetricsWriter struct {
	writeFunc func(metrics ...BlockDeviceMetrics) error
	metrics   []BlockDeviceMetrics
}

func (m *mockBlockDeviceMetricsWriter) Write(metrics ...BlockDeviceMetrics) error {
	if m.writeFunc != nil {
		return m.writeFunc(metrics...)
	}
	m.metrics = append(m.metrics, metrics...)
	return nil
}

type mockFilesystemMetricsWriter struct {
	writeFunc func(metrics ...FilesystemMetrics) error
	metrics   []FilesystemMetrics
}

func (m *mockFilesystemMetricsWriter) Write(metrics ...FilesystemMetrics) error {
	if m.writeFunc != nil {
		return m.writeFunc(metrics...)
	}
	m.metrics = append(m.metrics, metrics...)
	return nil
}

type mockDiskStatsProvider struct {
	ioCountersFunc  func() (map[string]disk.IOCountersStat, error)
	partitionsFunc  func(all bool) ([]disk.PartitionStat, error)
	usageFunc       func(path string) (*disk.UsageStat, error)
}

func (m *mockDiskStatsProvider) IOCounters() (map[string]disk.IOCountersStat, error) {
	if m.ioCountersFunc != nil {
		return m.ioCountersFunc()
	}
	return make(map[string]disk.IOCountersStat), nil
}

func (m *mockDiskStatsProvider) Partitions(all bool) ([]disk.PartitionStat, error) {
	if m.partitionsFunc != nil {
		return m.partitionsFunc(all)
	}
	return []disk.PartitionStat{}, nil
}

func (m *mockDiskStatsProvider) Usage(path string) (*disk.UsageStat, error) {
	if m.usageFunc != nil {
		return m.usageFunc(path)
	}
	return &disk.UsageStat{}, nil
}
