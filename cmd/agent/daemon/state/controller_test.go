package state

import (
	"context"
	"net/netip"
	"testing"
	"time"

	kubepb "github.com/castai/kvisor/api/v1/kube"
	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/enrichment"
	"github.com/castai/kvisor/cmd/agent/daemon/netstats"
	"github.com/castai/kvisor/pkg/cgroup"
	"github.com/castai/kvisor/pkg/containers"
	"github.com/castai/kvisor/pkg/ebpftracer"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/castai/kvisor/pkg/processtree"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
)

type testAddr struct {
	expected string
	raw      [16]byte
}

func TestController(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Run("events pipeline", func(t *testing.T) {
		r := require.New(t)
		ctrl := newTestController()
		exporter := &mockEventsExporter{events: make(chan *castaipb.Event, 10)}
		ctrl.exporters.Events = append(ctrl.exporters.Events, exporter)
		ctrl.tracer.(*mockEbpfTracer).eventsChan <- &types.Event{
			Context: &types.EventContext{Ts: 1},
			Container: &containers.Container{
				PodName: "p1",
			},
		}
		ctrlerr := make(chan error, 1)
		go func() {
			ctrlerr <- ctrl.Run(ctx)
		}()

		select {
		case e := <-exporter.events:
			r.Equal("p1", e.PodName)
		case err := <-ctrlerr:
			t.Fatal(err)
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for data")
		}
	})

	//t.Run("container stats pipeline", func(t *testing.T) {
	//	r := require.New(t)
	//	ctrl := newTestController()
	//	exporter := &mockContainerStatsExporter{events: make(chan *castaipb.ContainerStatsBatch, 10)}
	//	ctrl.exporters.ContainerStats = append(ctrl.exporters.ContainerStats, exporter)
	//	ctrl.tracer.(*mockEbpfTracer).syscallStats = map[ebpftracer.SyscallStatsKeyCgroupID][]ebpftracer.SyscallStats{
	//		1: {
	//			{ID: ebpftracer.SyscallID(2), Count: 3},
	//		},
	//	}
	//	ctrl.containersClient.(*mockContainersClient).list = []*containers.Container{
	//		{
	//			ID:           "c1",
	//			Name:         "cont",
	//			CgroupID:     1,
	//			PodNamespace: "ns1",
	//			PodUID:       "p1",
	//			PodName:      "p1",
	//			Cgroup:       nil,
	//		},
	//	}
	//
	//	ctrlerr := make(chan error, 1)
	//	go func() {
	//		ctrlerr <- ctrl.Run(ctx)
	//	}()
	//
	//	select {
	//	case e := <-exporter.events:
	//		r.Len(e.Items, 1)
	//		r.Len(e.Items[0].Stats, 1)
	//		r.Equal(1, int(e.Items[0].Stats[0].Group))
	//		r.Equal(2, int(e.Items[0].Stats[0].Subgroup))
	//		r.GreaterOrEqual(1, int(e.Items[0].Stats[0].Value))
	//	case err := <-ctrlerr:
	//		t.Fatal(err)
	//	case <-time.After(time.Second):
	//		t.Fatal("timed out waiting for data")
	//	}
	//})

	t.Run("netflow pipeline", func(t *testing.T) {
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
				PIDs: []uint32{1},
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
					"172.168.0.10",
					[16]byte{0xac, 0xa8, 0, 0xa},
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
				ctrl.tracer.(*mockEbpfTracer).sendNetflowTestEvent(tt.saddr.raw, tt.daddr.raw, tt.family)
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
					r.GreaterOrEqual(int(dest.TxBytes), 10)
					r.GreaterOrEqual(int(dest.TxPackets), 5)
				case err := <-ctrlerr:
					t.Fatal(err)
				case <-time.After(time.Second):
					t.Fatal("timed out waiting for data")
				}
			})
		}
	})
}

func (m *mockEbpfTracer) sendNetflowTestEvent(saddr, daddr [16]byte, family uint16) {
	m.netflowCollectChan <- map[ebpftracer.TrafficKey]ebpftracer.TrafficSummary{{
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
			Saddr:  struct{ Raw [16]uint8 }{Raw: saddr},
			Daddr:  struct{ Raw [16]uint8 }{Raw: daddr},
			Sport:  34561,
			Dport:  80,
			Family: family,
		},
		Proto: unix.IPPROTO_TCP,
	}: {
		TxBytes:   10,
		TxPackets: 5,
	}}
}

type customizeMockTracer func(t *mockEbpfTracer)
type customizeMockContainersClient func(t *mockContainersClient)

func newTestController(opts ...any) *Controller {
	log := logging.NewTestLog()
	cfg := Config{
		StatsScrapeInterval:   time.Millisecond,
		NetflowExportInterval: time.Millisecond,
	}
	exporters := NewExporters(log)
	contClient := &mockContainersClient{}
	contClientCustomizer := getOptOr[customizeMockContainersClient](opts, func(t *mockContainersClient) {})
	contClientCustomizer(contClient)

	netReader := &mockNetStatsReader{}
	ctClient := &mockConntrackClient{}

	tracer := &mockEbpfTracer{
		eventsChan:         make(chan *types.Event, 100),
		netflowCollectChan: make(chan map[ebpftracer.TrafficKey]ebpftracer.TrafficSummary, 100),
	}
	tracerCustomizer := getOptOr[customizeMockTracer](opts, func(t *mockEbpfTracer) {})
	tracerCustomizer(tracer)

	sigEngine := &mockSignatureEngine{eventsChan: make(chan *castaipb.Event, 100)}
	enrichService := &mockEnrichmentService{eventsChan: make(chan *castaipb.Event, 100)}
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
		enrichService,
		kubeClient,
		processTreeCollector,
		procHandler,
	)
	return ctrl
}

type mockEventsExporter struct {
	events chan *castaipb.Event
}

func (m *mockEventsExporter) Run(ctx context.Context) error {
	return nil
}

func (m *mockEventsExporter) Enqueue(e *castaipb.Event) {
	m.events <- e
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
	list []*containers.Container
}

func (m *mockContainersClient) GetCgroupStats(c *containers.Container) (cgroup.Stats, error) {
	return cgroup.Stats{}, nil
}

func (m *mockContainersClient) ListContainers() []*containers.Container {
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
	netflowCollectChan chan map[ebpftracer.TrafficKey]ebpftracer.TrafficSummary
}

func (m *mockEbpfTracer) CollectNetworkSummary() (map[ebpftracer.TrafficKey]ebpftracer.TrafficSummary, error) {
	select {
	case v := <-m.netflowCollectChan:
		return v, nil
	default:
		return map[ebpftracer.TrafficKey]ebpftracer.TrafficSummary{}, nil

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
	eventsChan chan *castaipb.Event
}

func (m *mockSignatureEngine) Events() <-chan *castaipb.Event {
	return m.eventsChan
}

type mockEnrichmentService struct {
	eventsChan chan *castaipb.Event
}

func (m *mockEnrichmentService) Events() <-chan *castaipb.Event {
	return m.eventsChan
}

func (m *mockEnrichmentService) Enqueue(e *enrichment.EnrichRequest) bool {
	return false
}

type mockKubeClient struct {
}

func (m *mockKubeClient) GetClusterInfo(ctx context.Context, in *kubepb.GetClusterInfoRequest, opts ...grpc.CallOption) (*kubepb.GetClusterInfoResponse, error) {
	return &kubepb.GetClusterInfoResponse{
		PodsCidr:    []string{"10.0.0.0/16", "fd00::/48"},
		ServiceCidr: []string{"172.168.0.0/16", "fd01::/48"},
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
}

func (m mockProcHandler) PSIEnabled() bool {
	return true
}

func (m mockProcHandler) GetPSIStats(file string) (*castaipb.PSIStats, error) {
	return &castaipb.PSIStats{}, nil
}

func (m mockProcHandler) GetMeminfoStats() (*castaipb.MemoryStats, error) {
	return &castaipb.MemoryStats{}, nil
}
