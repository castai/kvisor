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
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

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

	t.Run("container stats pipeline", func(t *testing.T) {
		r := require.New(t)
		ctrl := newTestController()
		exporter := &mockContainerStatsExporter{events: make(chan *castaipb.ContainerStatsBatch, 10)}
		ctrl.exporters.ContainerStats = append(ctrl.exporters.ContainerStats, exporter)
		ctrl.tracer.(*mockEbpfTracer).syscallStats = map[ebpftracer.SyscallStatsKeyCgroupID][]ebpftracer.SyscallStats{
			1: {
				{ebpftracer.SyscallID(2), 3},
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
				PIDs:         []uint32{1},
			},
		}

		ctrlerr := make(chan error, 1)
		go func() {
			ctrlerr <- ctrl.Run(ctx)
		}()

		select {
		case e := <-exporter.events:
			r.Len(e.Items, 1)
			r.Len(e.Items[0].Stats, 1)
			r.Equal(1, int(e.Items[0].Stats[0].Group))
			r.Equal(2, int(e.Items[0].Stats[0].Subgroup))
			r.GreaterOrEqual(1, int(e.Items[0].Stats[0].Value))
		case err := <-ctrlerr:
			t.Fatal(err)
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for data")
		}
	})

	t.Run("netflow pipeline", func(t *testing.T) {
		r := require.New(t)
		ctrl := newTestController()
		exporter := &mockNetflowExporter{events: make(chan *castaipb.Netflow, 10)}
		ctrl.exporters.Netflow = append(ctrl.exporters.Netflow, exporter)

		ctrl.tracer.(*mockEbpfTracer).netflowEventsChan <- &types.Event{
			Context: &types.EventContext{Ts: 1},
			Container: &containers.Container{
				PodName: "p1",
			},
			Args: types.NetFlowBaseArgs{
				Proto: 6,
				Tuple: types.AddrTuple{
					Src: netip.MustParseAddrPort("10.10.0.10:34561"),
					Dst: netip.MustParseAddrPort("10.10.0.15:80"),
				},
				TxBytes:   10,
				TxPackets: 5,
			},
		}

		ctrlerr := make(chan error, 1)
		go func() {
			ctrlerr <- ctrl.Run(ctx)
		}()

		select {
		case e := <-exporter.events:
			r.Equal(castaipb.NetflowProtocol_NETFLOW_PROTOCOL_TCP, e.Protocol)
			r.Equal(netip.MustParseAddr("10.10.0.10").AsSlice(), e.Addr)
			r.Equal(34561, int(e.Port))
			r.Len(e.Destinations, 1)
			dest := e.Destinations[0]
			r.Equal(netip.MustParseAddr("10.10.0.15").AsSlice(), dest.Addr)
			r.Equal(80, int(dest.Port))
			r.Equal(10, int(dest.TxBytes))
			r.Equal(5, int(dest.TxPackets))
		case err := <-ctrlerr:
			t.Fatal(err)
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for data")
		}
	})
}

func newTestController() *Controller {
	log := logging.NewTestLog()
	cfg := Config{
		ContainerStatsScrapeInterval: time.Millisecond,
		NetflowExportInterval:        time.Millisecond,
	}
	exporters := NewExporters(log)
	contClient := &mockContainersClient{}
	netReader := &mockNetStatsReader{}
	ctClient := &mockConntrackClient{}
	tracer := &mockEbpfTracer{eventsChan: make(chan *types.Event, 100), netflowEventsChan: make(chan *types.Event, 100)}
	sigEngine := &mockSignatureEngine{eventsChan: make(chan *castaipb.Event, 100)}
	enrichService := &mockEnrichmentService{eventsChan: make(chan *castaipb.Event, 100)}
	kubeClient := &mockKubeClient{}
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

type mockContainerStatsExporter struct {
	events chan *castaipb.ContainerStatsBatch
}

func (m *mockContainerStatsExporter) Run(ctx context.Context) error {
	return nil
}

func (m *mockContainerStatsExporter) Enqueue(e *castaipb.ContainerStatsBatch) {
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

func (m *mockContainersClient) GetCgroupCpuStats(c *containers.Container) (*cgroup.CPUStat, error) {
	return &cgroup.CPUStat{}, nil
}

func (m *mockContainersClient) GetCgroupMemoryStats(c *containers.Container) (*cgroup.MemoryStat, error) {
	return &cgroup.MemoryStat{}, nil
}

func (m *mockContainersClient) ListContainers() []*containers.Container {
	return m.list
}

func (m *mockContainersClient) GetContainerForCgroup(ctx context.Context, cgroup uint64) (*containers.Container, error) {
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

type mockEbpfTracer struct {
	eventsChan        chan *types.Event
	netflowEventsChan chan *types.Event
	syscallStats      map[ebpftracer.SyscallStatsKeyCgroupID][]ebpftracer.SyscallStats
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

func (m *mockEbpfTracer) NetflowEvents() <-chan *types.Event {
	return m.netflowEventsChan
}

func (m *mockEbpfTracer) MuteEventsFromCgroup(cgroup uint64) error {
	return nil
}

func (m *mockEbpfTracer) MuteEventsFromCgroups(cgroups []uint64) error {
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
		PodsCidr:    "10.0.0.0/16",
		ServiceCidr: "172.168.0.0/16",
	}, nil
}

func (m *mockKubeClient) GetIPInfo(ctx context.Context, in *kubepb.GetIPInfoRequest, opts ...grpc.CallOption) (*kubepb.GetIPInfoResponse, error) {
	return &kubepb.GetIPInfoResponse{
		Info: &kubepb.IPInfo{},
	}, nil
}

func (m *mockKubeClient) GetPod(ctx context.Context, in *kubepb.GetPodRequest, opts ...grpc.CallOption) (*kubepb.GetPodResponse, error) {
	return &kubepb.GetPodResponse{
		Pod: &kubepb.Pod{},
	}, nil
}
