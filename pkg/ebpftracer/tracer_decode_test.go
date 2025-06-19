package ebpftracer

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/castai/kvisor/pkg/cgroup"
	"github.com/castai/kvisor/pkg/containers"
	"github.com/castai/kvisor/pkg/ebpftracer/decoder"
	"github.com/castai/kvisor/pkg/ebpftracer/events"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/castai/kvisor/pkg/proc"
	"github.com/stretchr/testify/require"
)

var (
	errFilterFail = errors.New("")

	eventFilterFail EventFilterGenerator = GlobalEventFilterGenerator(
		func(event *types.Event) error {
			return errFilterFail
		},
	)
	eventFilterPass EventFilterGenerator = GlobalEventFilterGenerator(
		func(event *types.Event) error {
			return ErrFilterPass
		},
	)

	preEventFilterFail PreEventFilterGenerator = GlobalPreEventFilterGenerator(
		func(ctx *types.EventContext, d *decoder.Decoder) (types.Args, error) {
			return nil, errFilterFail
		},
	)
	preEventFilterPass PreEventFilterGenerator = GlobalPreEventFilterGenerator(
		func(ctx *types.EventContext, d *decoder.Decoder) (types.Args, error) {
			return nil, errFilterFail
		},
	)
)

func TestFilterDecodeAndExportEvent(t *testing.T) {
	type testCase struct {
		name        string
		policy      *Policy
		resultEmpty bool
	}

	r := require.New(t)

	testEventDataPath := filepath.Join("decoder", "testdata", "magic_write_event.bin")
	testEventData, err := os.ReadFile(testEventDataPath)
	r.NoError(err)

	testCases := []testCase{
		{
			name:        "empty policy should not drop event",
			resultEmpty: false,
		},
		{
			name: "only pre filter should drop event",
			policy: &Policy{
				Events: []*EventPolicy{
					{
						ID:                 events.TestEvent,
						PreFilterGenerator: preEventFilterFail,
					},
				},
			},
			resultEmpty: true,
		},
		{
			name: "only filter should drop event",
			policy: &Policy{
				Events: []*EventPolicy{
					{
						ID:              events.TestEvent,
						FilterGenerator: eventFilterFail,
					},
				},
			},
			resultEmpty: true,
		},
		{
			name: "pre filter false, but filter true should drop event",
			policy: &Policy{
				Events: []*EventPolicy{
					{
						ID:                 events.TestEvent,
						PreFilterGenerator: preEventFilterFail,
						FilterGenerator:    eventFilterPass,
					},
				},
			},
			resultEmpty: true,
		},
		{
			name: "pre filter true, but filter false should drop event",
			policy: &Policy{
				Events: []*EventPolicy{
					{
						ID:                 events.TestEvent,
						PreFilterGenerator: preEventFilterPass,
						FilterGenerator:    eventFilterFail,
					},
				},
			},
			resultEmpty: true,
		},
		{
			name: "should not process event there is no policy for",
			policy: &Policy{
				Events: []*EventPolicy{
					{
						ID: events.NetPacketDNSBase,
					},
				},
			},
			resultEmpty: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tracer := buildTestTracer()

			if tc.policy != nil {
				applyTestPolicy(tracer, tc.policy)
			}

			dec := decoder.NewEventDecoder(logging.NewTestLog(), testEventData)
			err := tracer.decodeAndExportEvent(context.TODO(), dec)
			require.NoError(t, err)

			if tc.resultEmpty {
				require.Empty(t, tracer.Events(), "there should be no event")
			} else {
				require.Len(t, tracer.Events(), 1, "there should be one event")
			}
		})
	}
}

func TestDecodeMagicWriteEvent(t *testing.T) {
	r := require.New(t)
	path := filepath.Join("decoder", "testdata", "magic_write_event.bin")
	data, err := os.ReadFile(path)
	r.NoError(err)

	dec := decoder.NewEventDecoder(logging.New(&logging.Config{}), data)

	tr := &Tracer{
		eventsChan: make(chan *types.Event),
		cfg:        Config{ContainerClient: newMockContainersClient()},
	}

	go func() {
		err = tr.decodeAndExportEvent(context.Background(), dec)
		r.NoError(err)
	}()

	e := <-tr.eventsChan

	r.EqualValues(events.MagicWrite, e.Context.EventID)
	r.IsType(types.MagicWriteArgs{}, e.Args)
	magicArgs := e.Args.(types.MagicWriteArgs)

	r.Equal("/tmp/tmp.u3Yro419hD/tar_executable", magicArgs.Pathname)
	r.Equal("f0VMRgIBAQAAAAAAAAAAAAMAtwABAAAAgL4AAAAAAAA=", base64.StdEncoding.EncodeToString(magicArgs.Bytes))
	r.EqualValues(0x122, magicArgs.Dev)
	r.EqualValues(0x403f00, magicArgs.Inode)
}

func TestDecodeSchedProcessExecEvent(t *testing.T) {
	r := require.New(t)

	mountNamespacePIDStore, err := types.NewPIDsPerNamespaceCache(1, 1)
	r.NoError(err)

	tr := &Tracer{
		eventsChan: make(chan *types.Event),
		cfg: Config{
			ContainerClient:        newMockContainersClient(),
			MountNamespacePIDStore: mountNamespacePIDStore,
		},
	}

	t.Run("add PID to the bucket", func(t *testing.T) {
		eventCtx, err := TracerEventContextT{
			Ts:      10,
			Eventid: uint32(events.SchedProcessExec),
			Task:    testTaskContext(),
		}.Encode()
		r.NoError(err)

		dec := decoder.NewEventDecoder(logging.New(&logging.Config{}), eventCtx)

		go func() {
			err = tr.decodeAndExportEvent(context.Background(), dec)
			r.NoError(err)
		}()

		e := <-tr.eventsChan

		r.EqualValues(events.SchedProcessExec, e.Context.EventID)
		bucket := mountNamespacePIDStore.GetBucket(proc.NamespaceID(testTaskContext().MntId))
		r.Equal([]proc.PID{testTaskContext().NodeHostPid}, bucket)
	})
}

func TestDecodeSchedProcessExitEvent(t *testing.T) {
	r := require.New(t)

	mountNamespacePIDStore, err := types.NewPIDsPerNamespaceCache(1, 3)
	r.NoError(err)

	// Add some PIDs to the bucket to simulate SchedProcessExec events
	mountNamespacePIDStore.ForceAddToBucket(proc.NamespaceID(testTaskContext().MntId), proc.PID(1))
	mountNamespacePIDStore.AddToBucket(proc.NamespaceID(testTaskContext().MntId), proc.PID(2))
	mountNamespacePIDStore.AddToBucket(proc.NamespaceID(testTaskContext().MntId), testTaskContext().NodeHostPid)

	tr := &Tracer{
		eventsChan: make(chan *types.Event),
		cfg: Config{
			ContainerClient:        newMockContainersClient(),
			MountNamespacePIDStore: mountNamespacePIDStore,
		},
	}

	exitEvent := TracerEventContextT{
		Ts:      10,
		Eventid: uint32(events.SchedProcessExit),
		Task:    testTaskContext(),
	}

	t.Run("remove PID from the bucket", func(t *testing.T) {
		eventCtx, err := exitEvent.Encode()
		r.NoError(err)

		dec := decoder.NewEventDecoder(logging.New(&logging.Config{}), eventCtx)

		go func() {
			err = tr.decodeAndExportEvent(context.Background(), dec)
			r.NoError(err)
		}()
		e := <-tr.eventsChan

		r.EqualValues(events.SchedProcessExit, e.Context.EventID)
		bucket := mountNamespacePIDStore.GetBucket(proc.NamespaceID(testTaskContext().MntId))
		r.Equal([]proc.PID{1, 2}, bucket)
	})

	t.Run("bucket is empty after removing PID 1", func(t *testing.T) {
		exitEvent.Task.Pid = 1
		eventCtx, err := exitEvent.Encode()
		r.NoError(err)

		dec := decoder.NewEventDecoder(logging.New(&logging.Config{}), eventCtx)

		go func() {
			err = tr.decodeAndExportEvent(context.Background(), dec)
			r.NoError(err)
		}()
		e := <-tr.eventsChan

		r.EqualValues(events.SchedProcessExit, e.Context.EventID)
		bucket := mountNamespacePIDStore.GetBucket(proc.NamespaceID(testTaskContext().MntId))
		r.Empty(bucket)
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
			}, nil
		},
	}
}

func testTaskContext() tracerTaskContextT {
	return tracerTaskContextT{
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
		Comm:        [16]uint8{0x48},
	}
}
