package signature

import (
	"testing"

	v1 "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/containers"
	"github.com/castai/kvisor/pkg/ebpftracer/events"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/stretchr/testify/require"
)

var socks5ClientRequestData = []byte{
	// IPv4 header
	0x45, 0x00, 0x00, 0x38, 0x3c, 0x23, 0x40, 0x00,
	0x40, 0x06, 0x00, 0x9b, 0x7f, 0x00, 0x00, 0x01,
	0x7f, 0x00, 0x00, 0x01, 0xae, 0x20, 0x04, 0x38,
	0xed, 0xbb, 0x47, 0xad, 0x77, 0x45, 0x5a, 0x21,
	0x80, 0x18, 0x02, 0x00, 0xfe, 0x2c, 0x00, 0x00,
	0x01, 0x01, 0x08, 0x0a, 0x3c, 0xfe, 0xe8, 0x88,
	0x3c, 0xfe, 0xe8, 0x88, 0x05, 0x02,

	// SOCKS5 start
	0x00, 0x01,
}

var socks5ServerMethodSelectData = []byte{
	// IPv4 header
	0x45, 0x00, 0x00, 0x36, 0x29, 0x67, 0x40, 0x00,
	0x40, 0x06, 0x13, 0x59, 0x7f, 0x00, 0x00, 0x01,
	0x7f, 0x00, 0x00, 0x01, 0x04, 0x38, 0xae, 0x20,
	0x77, 0x45, 0x5a, 0x21, 0xed, 0xbb, 0x47, 0xb1,
	0x80, 0x18, 0x02, 0x00, 0xfe, 0x2a, 0x00, 0x00,
	0x01, 0x01, 0x08, 0x0a, 0x3c, 0xfe, 0xe8, 0x89,
	0x3c, 0xfe, 0xe8, 0x88,

	// SOCKS5 start
	0x05, 0x00,
}

var socks5ClientConnectRequestData = []byte{
	// IPv4 header
	0x45, 0x00, 0x00, 0x3e, 0x3c, 0x25, 0x40, 0x00,
	0x40, 0x06, 0x00, 0x93, 0x7f, 0x00, 0x00, 0x01,
	0x7f, 0x00, 0x00, 0x01, 0xae, 0x20, 0x04, 0x38,
	0xed, 0xbb, 0x47, 0xb1, 0x77, 0x45, 0x5a, 0x23,
	0x80, 0x18, 0x02, 0x00, 0xfe, 0x32, 0x00, 0x00,
	0x01, 0x01, 0x08, 0x0a, 0x3c, 0xfe, 0xe8, 0x9b,
	0x3c, 0xfe, 0xe8, 0x89,

	// SOCKS5 start
	0x05,
	0x01, //connect
	0x00,
	0x01, // IPv4
	// IP data of 142.250.185.99
	0x8e, 0xfa, 0xb9, 0x63,
	// Port 80
	0x00, 0x50,
}

var socks5ServerConnectResponseData = []byte{
	// IPv4 header
	0x45, 0x00, 0x00, 0x3e, 0x29, 0x69, 0x40, 0x00,
	0x40, 0x06, 0x13, 0x4f, 0x7f, 0x00, 0x00, 0x01,
	0x7f, 0x00, 0x00, 0x01, 0x04, 0x38, 0xae, 0x20,
	0x77, 0x45, 0x5a, 0x23, 0xed, 0xbb, 0x47, 0xbb,
	0x80, 0x18, 0x02, 0x00, 0xfe, 0x32, 0x00, 0x00,
	0x01, 0x01, 0x08, 0x0a, 0x3c, 0xfe, 0xe8, 0xc9,
	0x3c, 0xfe, 0xe8, 0x9b,

	// SOCKS5 start
	0x05,
	0x00, // success
	0x00,
	0x01, // IPv4
	// IP data of 10.244.0.22
	0x0a, 0xf4, 0x00, 0x16,
	// Port 52330
	0xcc, 0x6a,
}

func TestSOCKS5DetectedSignature(t *testing.T) {
	type eventWithFinding struct {
		event           types.Event
		expectedFinding *v1.SignatureFinding
	}

	type testCase struct {
		title  string
		events []eventWithFinding
	}

	testCases := []testCase{
		{
			title: "should detect socks5 server",
			events: []eventWithFinding{
				{
					event: types.Event{
						Context: &types.EventContext{
							EventID:  events.NetPacketSOCKS5Base,
							Ts:       11,
							CgroupID: 10,
							Pid:      99,
							Retval:   types.FlagPacketIngress,
						},
						Container: &containers.Container{
							ID:       "123",
							Name:     "name-123",
							CgroupID: 10,
						},
						Args: types.NetPacketSOCKS5BaseArgs{
							Payload: socks5ClientRequestData,
						},
					},
				},
				{
					event: types.Event{
						Context: &types.EventContext{
							EventID:  events.NetPacketSOCKS5Base,
							Ts:       12,
							CgroupID: 10,
							Pid:      99,
							Retval:   types.FlagPacketEgress,
						},
						Container: &containers.Container{
							ID:       "123",
							Name:     "name-123",
							CgroupID: 10,
						},
						Args: types.NetPacketSOCKS5BaseArgs{
							Payload: socks5ServerMethodSelectData,
						},
					},
				},
				{
					event: types.Event{
						Context: &types.EventContext{
							EventID:  events.NetPacketSOCKS5Base,
							Ts:       13,
							CgroupID: 10,
							Pid:      99,
							Retval:   types.FlagPacketIngress,
						},
						Container: &containers.Container{
							ID:       "123",
							Name:     "name-123",
							CgroupID: 10,
						},
						Args: types.NetPacketSOCKS5BaseArgs{
							Payload: socks5ClientConnectRequestData,
						},
					},
					expectedFinding: &v1.SignatureFinding{
						Data: &v1.SignatureFinding_Socks5Detected{
							Socks5Detected: &v1.SOCKS5DetectedFinding{
								Role:          v1.SOCKS5Role_SOCKS5_ROLE_SERVER,
								FlowDirection: v1.FlowDirection_FLOW_INGRESS,
								CmdOrReply:    0x01,
								AddressType:   v1.SOCKS5AddressType_SOCKS5_ADDRESS_TYPE_IPv4,
								Address:       []byte{0x8e, 0xfa, 0xb9, 0x63},
								Port:          80,
							},
						},
					},
				},
				{
					event: types.Event{
						Context: &types.EventContext{
							EventID:  events.NetPacketSOCKS5Base,
							Ts:       13,
							CgroupID: 10,
							Pid:      99,
							Retval:   types.FlagPacketEgress,
						},
						Container: &containers.Container{
							ID:       "123",
							Name:     "name-123",
							CgroupID: 10,
						},
						Args: types.NetPacketSOCKS5BaseArgs{
							Payload: socks5ServerConnectResponseData,
						},
					},
					expectedFinding: &v1.SignatureFinding{
						Data: &v1.SignatureFinding_Socks5Detected{
							Socks5Detected: &v1.SOCKS5DetectedFinding{
								Role:          v1.SOCKS5Role_SOCKS5_ROLE_SERVER,
								FlowDirection: v1.FlowDirection_FLOW_EGRESS,
								CmdOrReply:    0x00,
								AddressType:   v1.SOCKS5AddressType_SOCKS5_ADDRESS_TYPE_IPv4,
								Address:       []byte{0x0a, 0xf4, 0x00, 0x16},
								Port:          52330,
							},
						},
					},
				},
			},
		},
		{
			title: "should detect socks5 client",
			events: []eventWithFinding{
				{
					event: types.Event{
						Context: &types.EventContext{
							EventID:  events.NetPacketSOCKS5Base,
							Ts:       11,
							CgroupID: 10,
							Pid:      99,
							Retval:   types.FlagPacketEgress,
						},
						Container: &containers.Container{
							ID:       "123",
							Name:     "name-123",
							CgroupID: 10,
						},
						Args: types.NetPacketSOCKS5BaseArgs{
							Payload: socks5ClientRequestData,
						},
					},
				},
				{
					event: types.Event{
						Context: &types.EventContext{
							EventID:  events.NetPacketSOCKS5Base,
							Ts:       12,
							CgroupID: 10,
							Pid:      99,
							Retval:   types.FlagPacketIngress,
						},
						Container: &containers.Container{
							ID:       "123",
							Name:     "name-123",
							CgroupID: 10,
						},
						Args: types.NetPacketSOCKS5BaseArgs{
							Payload: socks5ServerMethodSelectData,
						},
					},
				},
				{
					event: types.Event{
						Context: &types.EventContext{
							EventID:  events.NetPacketSOCKS5Base,
							Ts:       13,
							CgroupID: 10,
							Pid:      99,
							Retval:   types.FlagPacketEgress,
						},
						Container: &containers.Container{
							ID:       "123",
							Name:     "name-123",
							CgroupID: 10,
						},
						Args: types.NetPacketSOCKS5BaseArgs{
							Payload: socks5ClientConnectRequestData,
						},
					},
					expectedFinding: &v1.SignatureFinding{
						Data: &v1.SignatureFinding_Socks5Detected{
							Socks5Detected: &v1.SOCKS5DetectedFinding{
								Role:          v1.SOCKS5Role_SOCKS5_ROLE_CLIENT,
								FlowDirection: v1.FlowDirection_FLOW_EGRESS,
								CmdOrReply:    0x01,
								AddressType:   v1.SOCKS5AddressType_SOCKS5_ADDRESS_TYPE_IPv4,
								Address:       []byte{0x8e, 0xfa, 0xb9, 0x63},
								Port:          80,
							},
						},
					},
				},
				{
					event: types.Event{
						Context: &types.EventContext{
							EventID:  events.NetPacketSOCKS5Base,
							Ts:       13,
							CgroupID: 10,
							Pid:      99,
							Retval:   types.FlagPacketIngress,
						},
						Container: &containers.Container{
							ID:       "123",
							Name:     "name-123",
							CgroupID: 10,
						},
						Args: types.NetPacketSOCKS5BaseArgs{
							Payload: socks5ServerConnectResponseData,
						},
					},
					expectedFinding: &v1.SignatureFinding{
						Data: &v1.SignatureFinding_Socks5Detected{
							Socks5Detected: &v1.SOCKS5DetectedFinding{
								Role:          v1.SOCKS5Role_SOCKS5_ROLE_CLIENT,
								FlowDirection: v1.FlowDirection_FLOW_INGRESS,
								CmdOrReply:    0x00,
								AddressType:   v1.SOCKS5AddressType_SOCKS5_ADDRESS_TYPE_IPv4,
								Address:       []byte{0x0a, 0xf4, 0x00, 0x16},
								Port:          52330,
							},
						},
					},
				},
			},
		},
		{
			title: "should detect socks5 on only connect message",
			events: []eventWithFinding{
				{
					event: types.Event{
						Context: &types.EventContext{
							EventID:  events.NetPacketSOCKS5Base,
							Ts:       13,
							CgroupID: 10,
							Pid:      99,
							Retval:   types.FlagPacketEgress,
						},
						Container: &containers.Container{
							ID:       "123",
							Name:     "name-123",
							CgroupID: 10,
						},
						Args: types.NetPacketSOCKS5BaseArgs{
							Payload: socks5ClientConnectRequestData,
						},
					},
					expectedFinding: &v1.SignatureFinding{
						Data: &v1.SignatureFinding_Socks5Detected{
							Socks5Detected: &v1.SOCKS5DetectedFinding{
								Role:          v1.SOCKS5Role_SOCKS5_ROLE_UNKNOWN,
								FlowDirection: v1.FlowDirection_FLOW_EGRESS,
								CmdOrReply:    0x01,
								AddressType:   v1.SOCKS5AddressType_SOCKS5_ADDRESS_TYPE_IPv4,
								Address:       []byte{0x8e, 0xfa, 0xb9, 0x63},
								Port:          80,
							},
						},
					},
				},
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.title, func(t *testing.T) {
			r := require.New(t)

			signature, err := NewSOCKS5DetectedSignature(SOCKS5DetectionSignatureConfig{})
			r.NoError(err)

			for i, e := range test.events {
				result := signature.OnEvent(&e.event)

				if e.expectedFinding == nil {
					r.Nil(result)
					continue
				}
				r.Equal(e.expectedFinding, result, "match finding for event nr. %d: %d", i, e.event.Context.EventID)
			}
		})
	}
}
