package signature

import (
	"net/netip"
	"testing"

	v1 "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/containers"
	"github.com/castai/kvisor/pkg/ebpftracer/events"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/stretchr/testify/require"
)

func TestTtyDetectedSignature(t *testing.T) {
	type testCase struct {
		title           string
		event           types.Event
		expectedFinding *v1.SignatureFinding
	}

	testCases := []testCase{
		{
			title: "should fire for tty open event",
			event: types.Event{
				Context: &types.EventContext{
					EventID:  events.TtyOpen,
					Ts:       11,
					CgroupID: 10,
					Pid:      99,
				},
				Container: &containers.Container{
					ID:       "123",
					Name:     "name-123",
					CgroupID: 10,
				},
				Args: types.TtyOpenArgs{
					Path:      "/dev/ptyt0",
					Inode:     10,
					InodeMode: 0,
					Dev:       2,
				},
			},
			expectedFinding: &v1.SignatureFinding{
				Data: &v1.SignatureFinding_TtyDetected{
					TtyDetected: &v1.TtyDetectedFinding{
						Path: "/dev/ptyt0",
					},
				},
			},
		},
		{
			title: "should not fire for random event",
			event: types.Event{
				Context: &types.EventContext{
					EventID:  events.SecuritySocketConnect,
					Ts:       11,
					CgroupID: 10,
					Pid:      99,
				},
				Container: &containers.Container{
					ID:       "123",
					Name:     "name-123",
					CgroupID: 10,
				},
				Args: types.SecuritySocketConnectArgs{
					Sockfd: 10,
					Type:   0,
					RemoteAddr: types.Ip4SockAddr{
						Addr: netip.MustParseAddrPort("1.2.3.4:1190"),
					},
				},
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.title, func(t *testing.T) {
			r := require.New(t)

			signature := NewTTYDetectedSignature()

			result := signature.OnEvent(&test.event)

			if test.expectedFinding == nil {
				r.Nil(result)
				return
			}

			r.Equal(test.expectedFinding, result)
		})
	}
}
