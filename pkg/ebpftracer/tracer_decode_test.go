package ebpftracer

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/castai/kvisor/pkg/cgroup"
	"github.com/castai/kvisor/pkg/containers"
	"github.com/castai/kvisor/pkg/ebpftracer/decoder"
	"github.com/castai/kvisor/pkg/ebpftracer/events"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/castai/kvisor/pkg/processtree"
	"github.com/stretchr/testify/require"
)

func TestDecodeAndExport(t *testing.T) {
	t.Run("decode and export", func(t *testing.T) {
		r := require.New(t)
		path := filepath.Join("testdata", "event_6798_sched_process_exec_1739298072516672900.bin")
		data, err := os.ReadFile(path)
		r.NoError(err)

		dec := decoder.NewEventDecoder(logging.New(&logging.Config{}), data)

		tr := buildTestTracer()

		err = tr.decodeAndExportEvent(context.Background(), dec)
		r.NoError(err)

		e := <-tr.eventsChan

		r.Equal(types.EventContext{
			Ts:              tr.bootTime + 30389282067724,
			StartTime:       0x1ba38e5ac3f0,
			CgroupID:        0x1a8e,
			Pid:             0x27698a,
			Tid:             0x27698a,
			Ppid:            0x24ea83,
			HostPid:         0x283051,
			HostTid:         0x283051,
			HostPpid:        0x25af55,
			NodeHostPid:     0x283051,
			Uid:             0x0,
			MntID:           0xf00002c6,
			PidID:           0xf00002c9,
			Comm:            [16]uint8{0x72, 0x75, 0x6e, 0x63, 0x0, 0x69, 0x6e, 0x65, 0x72, 0x64, 0x2d, 0x73, 0x68, 0x69, 0x6d, 0x0},
			LeaderStartTime: 0x1ba38e5ac3f0,
			ParentStartTime: 0x1b5dae7fcd44,
			EventID:         events.SchedProcessExec,
			Syscall:         221,
			Retval:          0,
			ProcessorId:     0x1,
		}, *e.Context)

		r.IsType(types.SchedProcessExecArgs{}, e.Args)
		args := e.Args.(types.SchedProcessExecArgs)

		r.Equal("/usr/local/sbin/runc", args.Filepath)
		r.Equal([]string{
			"runc",
			"--root",
			"/run/containerd/runc/k8s.io",
			"--log",
			"/run/containerd/io.containerd.runtime.v2.task/k8s.io/83b73d88e4db46ec3328c704a6800f53597124aeaad2c98915ccdc5880b3d89d/log.json",
			"--log-format",
			"json",
			"--systemd-cgroup",
			"kill",
			"--all",
			"83b73d88e4db46ec3328c704a6800f53597124aeaad2c98915ccdc5880b3d89d",
			"9",
		}, args.Argv)
	})

	t.Run("skip duplicate dns event", func(t *testing.T) {
		r := require.New(t)
		path := filepath.Join("testdata", "event_37847_net_packet_dns_base_1739298127467113088.bin")
		data, err := os.ReadFile(path)
		r.NoError(err)

		dec := decoder.NewEventDecoder(logging.New(&logging.Config{}), data)

		tr := buildTestTracer()

		// First event, should be exported.
		err = tr.decodeAndExportEvent(context.Background(), dec)
		r.NoError(err)
		e := <-tr.eventsChan
		r.EqualValues(events.NetPacketDNSBase, e.Context.EventID)
		r.IsType(types.NetPacketDNSBaseArgs{}, e.Args)
		args := e.Args.(types.NetPacketDNSBaseArgs)

		r.Equal("echo-a-ipv6.kvisor-e2e.svc.cluster.local", args.Payload.DNSQuestionDomain)
		r.Len(args.Payload.Answers, 1)
		ip, _ := netip.AddrFromSlice(args.Payload.Answers[0].Ip[:])
		r.Equal("fd00:10:96::3dab", ip.String())

		// Second duplicate event for the same cgroup. Should be skipped.
		dec.Reset(data)
		err = tr.decodeAndExportEvent(context.Background(), dec)
		r.ErrorIs(err, errFoundFingerprint)

		// Simulate fingerprint expire. Event should be exported
		tr.fingerprints.Purge()
		dec.Reset(data)
		err = tr.decodeAndExportEvent(context.Background(), dec)
		r.NoError(err)
	})

	t.Run("skip duplicate tcp event", func(t *testing.T) {
		r := require.New(t)
		path := filepath.Join("testdata", "event_17701_sock_set_state_1739300123549602587.bin")
		data, err := os.ReadFile(path)
		r.NoError(err)

		dec := decoder.NewEventDecoder(logging.New(&logging.Config{}), data)

		tr := buildTestTracer()

		// First event, should be exported.
		err = tr.decodeAndExportEvent(context.Background(), dec)
		r.NoError(err)
		e := <-tr.eventsChan
		r.EqualValues(events.SockSetState, e.Context.EventID)
		r.IsType(types.SockSetStateArgs{}, e.Args)
		args := e.Args.(types.SockSetStateArgs)

		r.Equal("10.244.0.19:53158", args.Tuple.Src.String())
		r.Equal("34.120.177.193:443", args.Tuple.Dst.String())
		r.Equal(uint32(2), args.OldState)
		r.Equal(uint32(1), args.NewState)

		// Second duplicate event for the same cgroup. Should be skipped.
		dec.Reset(data)
		err = tr.decodeAndExportEvent(context.Background(), dec)
		r.ErrorIs(err, errFoundFingerprint)
	})
}

func newMockContainersClient() *MockContainerClient {
	return &MockContainerClient{
		ContainerGetter: func(ctx context.Context, cgroupID uint64) (*containers.Container, error) {
			dummyContainerID := fmt.Sprint(cgroupID)
			return &containers.Container{
				ID:           dummyContainerID,
				Name:         "dummy-container",
				CgroupID:     cgroupID,
				PodNamespace: "default",
				PodUID:       dummyContainerID,
				PodName:      "dummy-container-" + dummyContainerID,
				Cgroup: &cgroup.Cgroup{
					Id:               cgroupID,
					ContainerRuntime: cgroup.ContainerdRuntime,
					ContainerID:      dummyContainerID,
				},
				PIDs: []uint32{},
			}, nil
		},
	}
}

func buildTestEventContext() TracerEventContextT {
	return TracerEventContextT{
		Ts: 11,
		Task: tracerTaskContextT{
			CgroupId:    22,
			Pid:         543,
			Tid:         77,
			Ppid:        4567,
			HostPid:     5430,
			HostTid:     124,
			HostPpid:    555,
			NodeHostPid: 21345,
			Uid:         98123,
			MntId:       1357,
			PidId:       3758,
			Comm:        [16]int8{0x48},
		},
		Eventid: uint32(events.ProcessOomKilled),
	}
}

func buildTestEventData(t *testing.T, ctx TracerEventContextT, argsBytes []byte) []byte {
	dataBuf := &bytes.Buffer{}

	err := binary.Write(dataBuf, binary.LittleEndian, ctx)
	require.NoError(t, err)

	// writes argument length
	err = binary.Write(dataBuf, binary.LittleEndian, uint8(0))
	require.NoError(t, err)

	return dataBuf.Bytes()
}

type tracerOption func(*Tracer)

func buildTestTracer(options ...tracerOption) *Tracer {
	log := logging.New(&logging.Config{
		Level: slog.LevelDebug,
	})

	pidsStore, _ := types.NewPIDsPerNamespaceCache(100, 10)

	cfg := Config{
		BTFPath:                    "",
		SignalEventsRingBufferSize: 10,
		EventsRingBufferSize:       10,
		SkbEventsRingBufferSize:    10,
		EventsOutputChanSize:       10,
		DefaultCgroupsVersion:      "V1",
		DebugEnabled:               false,
		AutomountCgroupv2:          false,
		ContainerClient: &MockContainerClient{
			ContainerGetter: func(ctx context.Context, cg uint64) (*containers.Container, error) {
				return &containers.Container{
					CgroupID: cg,
					Cgroup: &cgroup.Cgroup{
						Id: cg,
					},
				}, nil
			},
		},
		CgroupClient:                       &MockCgroupClient{},
		SignatureEngine:                    nil,
		MountNamespacePIDStore:             pidsStore,
		HomePIDNS:                          0,
		AllowAnyEvent:                      false,
		NetflowSampleSubmitIntervalSeconds: 0,
		NetflowGrouping:                    0,
		TrackSyscallStats:                  false,
		ProcessTreeCollector:               processtree.NewNoop(),
		MetricsReporting:                   MetricsReportingConfig{},
		PodName:                            "",
		FingerprintSize:                    100,
	}
	tracer := New(log, cfg)
	tracer.eventsSet = newEventsDefinitionSet(&tracerObjects{})

	for _, option := range options {
		option(tracer)
	}

	return tracer
}

var _ CgroupClient = MockCgroupClient{}

type MockCgroupClient struct {
	CgroupLoader            func(id cgroup.ID, path string)
	CgroupCleaner           func(cgroup cgroup.ID)
	DefaultHierarchyChecker func(hierarchyID uint32) bool
}

func (m MockCgroupClient) GetCgroupsRootPath() string {
	return "/sys/fs/cgroup"
}

func (m MockCgroupClient) IsDefaultHierarchy(hierarchyID uint32) bool {
	if m.DefaultHierarchyChecker != nil {
		return m.DefaultHierarchyChecker(hierarchyID)
	}

	return true
}

func (m MockCgroupClient) CleanupCgroup(cgroup cgroup.ID) {
	if m.CgroupCleaner != nil {
		m.CgroupCleaner(cgroup)
	}
}

func (m MockCgroupClient) LoadCgroup(id cgroup.ID, path string) {
	if m.CgroupLoader != nil {
		m.CgroupLoader(id, path)
	}
}

type MockContainerClient struct {
	ContainerGetter func(ctx context.Context, cgroup uint64) (*containers.Container, error)
	CgroupCleaner   func(cgroup uint64)
}

func (c *MockContainerClient) AddContainerByCgroupID(ctx context.Context, cgroupID cgroup.ID) (cont *containers.Container, rerrr error) {
	return nil, nil
}

func (c *MockContainerClient) GetOrLoadContainerByCgroupID(ctx context.Context, cgroup uint64) (*containers.Container, error) {
	if c.ContainerGetter == nil {
		return nil, nil
	}

	return c.ContainerGetter(ctx, cgroup)
}

func (c *MockContainerClient) CleanupCgroup(cgroup uint64) {
	if c.CgroupCleaner == nil {
		return
	}

	c.CgroupCleaner(cgroup)
}
