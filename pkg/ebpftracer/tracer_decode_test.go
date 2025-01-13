package ebpftracer

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
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
			return FilterPass
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

	testEventDataPath := filepath.Join("decoder", "testdata", "event.bin")
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

func TestDecodeAndExport(t *testing.T) {
	r := require.New(t)
	path := filepath.Join("decoder", "testdata", "event.bin")
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

func buildTestEventData(t *testing.T) []byte {
	ctx := TracerEventContextT{
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

	dataBuf := &bytes.Buffer{}

	err := binary.Write(dataBuf, binary.LittleEndian, ctx)
	require.NoError(t, err)

	// writes argument length
	err = binary.Write(dataBuf, binary.LittleEndian, uint8(0))
	require.NoError(t, err)

	return dataBuf.Bytes()
}
