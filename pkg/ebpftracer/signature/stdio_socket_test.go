package signature

import (
	"net/netip"
	"testing"

	v1 "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/containers"
	"github.com/castai/kvisor/pkg/ebpftracer/events"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/stretchr/testify/require"
)

func TestStdioOverSocketSignature(t *testing.T) {
	type testCase struct {
		title           string
		event           types.Event
		expectedFinding *v1.SignatureFinding
	}

	testCases := []testCase{
		{
			title: "should fire for security socket connect event with stdio over socket",
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
					Sockfd: 0,
					Type:   0,
					RemoteAddr: types.Ip4SockAddr{
						Addr: netip.MustParseAddrPort("1.2.3.4:1190"),
					},
				},
			},
			expectedFinding: &v1.SignatureFinding{
				Data: &v1.SignatureFinding_StdioViaSocket{
					StdioViaSocket: &v1.StdioViaSocketFinding{
						Ip:       netip.MustParseAddr("1.2.3.4").AsSlice(),
						Port:     1190,
						Socketfd: 0,
					},
				},
			},
		},
		{
			title: "should not fire for security socket connect event with socket not stdio",
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
		{
			title: "should fire for socket dup event with new fs being stdio",
			event: types.Event{
				Context: &types.EventContext{
					EventID:  events.SocketDup,
					Ts:       11,
					CgroupID: 10,
					Pid:      99,
				},
				Container: &containers.Container{
					ID:       "123",
					Name:     "name-123",
					CgroupID: 10,
				},
				Args: types.SocketDupArgs{
					Oldfd:      10,
					Newfd:      0,
					RemoteAddr: types.Ip4SockAddr{Addr: netip.MustParseAddrPort("1.2.3.4:1190")},
				},
			},
			expectedFinding: &v1.SignatureFinding{
				Data: &v1.SignatureFinding_StdioViaSocket{
					StdioViaSocket: &v1.StdioViaSocketFinding{
						Ip:       netip.MustParseAddr("1.2.3.4").AsSlice(),
						Port:     1190,
						Socketfd: 0,
					},
				},
			},
		},
		{
			title: "should not fire for socket dup event with old fs not being stdio",
			event: types.Event{
				Context: &types.EventContext{
					EventID:  events.SocketDup,
					Ts:       11,
					CgroupID: 10,
					Pid:      99,
				},
				Container: &containers.Container{
					ID:       "123",
					Name:     "name-123",
					CgroupID: 10,
				},
				Args: types.SocketDupArgs{
					Oldfd:      5,
					Newfd:      10,
					RemoteAddr: types.Ip4SockAddr{Addr: netip.MustParseAddrPort("1.2.3.4:1190")},
				},
			},
		},
		{
			title: "should not fire for random event",
			event: types.Event{
				Context: &types.EventContext{
					EventID:  events.Chroot,
					Ts:       11,
					CgroupID: 10,
					Pid:      99,
				},
				Container: &containers.Container{
					ID:       "123",
					Name:     "name-123",
					CgroupID: 10,
				},
				Args: types.ChrootArgs{},
			},
		},
	}

	log := logging.New(&logging.Config{})

	for _, test := range testCases {
		t.Run(test.title, func(t *testing.T) {
			r := require.New(t)

			signature := NewStdViaSocketSignature(log)

			result := signature.OnEvent(&test.event)

			if test.expectedFinding == nil {
				r.Nil(result)
				return
			}

			r.Equal(test.expectedFinding, result)
		})
	}
}
