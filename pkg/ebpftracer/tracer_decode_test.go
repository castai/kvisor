package ebpftracer

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

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
		func(ctx *types.EventContext) error {
			return errFilterFail
		},
	)
	preEventFilterPass PreEventFilterGenerator = GlobalPreEventFilterGenerator(
		func(ctx *types.EventContext) error {
			return errFilterFail
		},
	)
)

func TestFilterDecodeAndExportEvent(t *testing.T) {
	type testCase struct {
		name        string
		policy      *Policy
		resultEmpty bool
	}

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
						ID: events.NetPacketDNS,
					},
				},
			},
			resultEmpty: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data := buildTestEventData(t)
			tracer := buildTestTracer()

			if tc.policy != nil {
				applyTestPolicy(tracer, tc.policy)
			}

			dec := decoder.NewEventDecoder(logging.NewTestLog(), data)
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

func TestDecodeContextAndArgs(t *testing.T) {
  t.SkipNow()
	r := require.New(t)
	testData := `jiaTS5ueBQB04qDEFpcFABDsAQAAAAAAAQAAADkAAAAAAAAABo0AAE2OAAC4jAAABo0AAAAAAAAoBgDwKQYA8GNvc3QtcmVwb3J0AAAAAABjb3N0LXJlcG9ydC1kZmQAAAAAAAAAAACLxYMoFZcFAICa8dYUlwUAEQMAACoAAAABAAAAAAAAAAAAAAAAAAAAAAAAABsAAAAEAAIAAAABAQAAAAIKFF7VAAAAAAAAAAAAAAAACh4AqwAAAAAAAAAAAAAAADyzkB8CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==`
	// testData := `WFpooR17AwAJJW8HbXMDABpwAQAAAAAAAQAAAEEAAAAAAAAAtWgYAEJrGABvaBgAtWgYAAAAAABnBQDwaAUA8GNvc3QtcmVwb3J0AAAAAABjb3N0LXJlcG9ydC1kZmQAAAAAAAAAAAColQtZa3MDAPvj4UxrcwMAEQMAACoAAAABAAAAAAAAAAAAAAAAAAAAAAAAABoAAAAGAAIAAAABAQAAAAIKFBrHAAAAAAAAAAAAAAAACh4AqwAAAAAAAAAAAAAAAMCwkB8CAAAAAAAAAQEAAAACChQaxwAAAAAAAAAAAAAAAAoeAKsAAAAAAAAAAAAAAAD0sJAfAgAA`
	// testData := `r3f6R8Z7AwACqW+f3XcDAF5NAQAAAAAAAQAAAKJOAAAAAAAAlWsPADEoFQBAaw8AlWsPAAAAAAAUCQDwGgkA8GNvc3QtcmVwb3J0AAAAAABjb3N0LXJlcG9ydC1kZmQAAAAAAAAAAADUcd3p/HADAGDFWI/8cAMAEQMAACoAAAABAAAAAAAAAAAAAAAAAAAAAAAAAB4AAAAGAAIAAAABAQAAAAIKFAheAAAAAAAAAAAAAAAACh4AqwAAAAAAAAAAAAAAAGyxkB8CAAAAAAAAAQEAAAACChQIXgAAAAAAAAAAAAAAAAoeAKsAAAAAAAAAAAAAAACqsZAfAgBr`
	data, err := base64.StdEncoding.DecodeString(testData)
	r.NoError(err)
	fmt.Println(len(data))

	decoder := decoder.NewEventDecoder(logging.New(&logging.Config{}), data)

	eventCtx, args, err := decodeContextAndArgs(decoder)
	r.NoError(err)

	r.EqualValues(785, eventCtx.EventID)
	r.IsType(types.SockSetStateArgs{}, args)
	d, err := json.Marshal(args)
	r.NoError(err)
	fmt.Println(string(d))

	// var eventCtx types.EventContext
	// err = decoder.DecodeContext(&eventCtx)
	// r.NoError(err)
	// var numArgs uint8
	// err = decoder.DecodeUint8(&numArgs)
	// r.NoError(err)
	// fmt.Println("num args:", numArgs)
	//
	// var curArg uint8
	// err = decoder.DecodeUint8(&curArg)
	// r.NoError(err)
	// var oldState uint32
	// err = decoder.DecodeUint32(&oldState)
	// r.NoError(err)
	//
	// fmt.Println(curArg, oldState)
	//
	// fmt.Println(eventCtx.Ts)
}

func buildTestEventData(t *testing.T) []byte {
	ctx := types.EventContext{
		EventID:     events.ProcessOomKilled,
		Ts:          11,
		CgroupID:    22,
		ProcessorId: 5,
		Pid:         543,
		Tid:         77,
		Ppid:        4567,
		HostPid:     5430,
		HostTid:     124,
		HostPpid:    555,
		Uid:         9876,
		MntID:       1357,
		PidID:       3758,
		Comm:        [16]byte{1, 3, 5, 3, 1, 5, 56, 6, 7, 32, 2, 4},
		UtsName:     [16]byte{5, 6, 7, 8, 9, 4, 3, 2},
		Retval:      0,
		StackID:     0,
	}

	dataBuf := &bytes.Buffer{}

	err := binary.Write(dataBuf, binary.LittleEndian, ctx)
	require.NoError(t, err)

	// writes argument length
	err = binary.Write(dataBuf, binary.LittleEndian, uint8(0))
	require.NoError(t, err)

	return dataBuf.Bytes()
}
