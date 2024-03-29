package ebpftracer

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"testing"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/ebpftracer/events"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/net/packet"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/google/gopacket/layers"
)

var (
	errFilterFail = errors.New("")

	eventFilterFail EventFilterGenerator = GlobalEventFilterGenerator(
		func(event *castpb.Event) error {
			return errFilterFail
		},
	)
	eventFilterPass EventFilterGenerator = GlobalEventFilterGenerator(
		func(event *castpb.Event) error {
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

			err := tracer.decodeAndExportEvent(context.TODO(), data)
			require.NoError(t, err)

			if tc.resultEmpty {
				require.Empty(t, tracer.Events(), "there should be no event")
			} else {
				require.Len(t, tracer.Events(), 1, "there should be one event")
			}
		})

	}
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

type dnsRecord struct {
	dnsType uint32
	name    string
	ip      string
}

type dnsData struct {
	question string
	answers  []dnsRecord
}

var udpDnsData = dnsData{
	question: "orf.at",
	answers: []dnsRecord{
		{uint32(dnsmessage.TypeA), "orf.at", "194.232.104.142"},
		{uint32(dnsmessage.TypeA), "orf.at", "194.232.104.150"},
		{uint32(dnsmessage.TypeA), "orf.at", "194.232.104.141"},
		{uint32(dnsmessage.TypeA), "orf.at", "194.232.104.4"},
		{uint32(dnsmessage.TypeA), "orf.at", "194.232.104.140"},
		{uint32(dnsmessage.TypeA), "orf.at", "194.232.104.149"},
		{uint32(dnsmessage.TypeA), "orf.at", "194.232.104.139"},
		{uint32(dnsmessage.TypeA), "orf.at", "194.232.104.3"},
	},
}
var dnsOverUDP4 = []byte{
	// IP header
	0x45, 0x00, 0x00, 0xe4, 0xb4, 0x0c, 0x40, 0x00, 0x3f, 0x11, 0x71, 0x44, 0x0a, 0x60, 0x00, 0x0a,
	0x0a, 0xf4, 0x00, 0x5b,

	// UDP header
	0x00, 0x35, 0xc5, 0x78, 0x00, 0xd0, 0x16, 0x9a,

	// DNS message
	0xc2, 0x3b, 0x81, 0x80, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x03, 0x6f, 0x72, 0x66,
	0x02, 0x61, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01, 0x03, 0x6f, 0x72, 0x66, 0x02, 0x61, 0x74, 0x00,
	0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x8e, 0x03, 0x6f,
	0x72, 0x66, 0x02, 0x61, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x04,
	0xc2, 0xe8, 0x68, 0x96, 0x03, 0x6f, 0x72, 0x66, 0x02, 0x61, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x1e, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x8d, 0x03, 0x6f, 0x72, 0x66, 0x02, 0x61,
	0x74, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x04,
	0x03, 0x6f, 0x72, 0x66, 0x02, 0x61, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1e,
	0x00, 0x04, 0xc2, 0xe8, 0x68, 0x8c, 0x03, 0x6f, 0x72, 0x66, 0x02, 0x61, 0x74, 0x00, 0x00, 0x01,
	0x00, 0x01, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x95, 0x03, 0x6f, 0x72, 0x66,
	0x02, 0x61, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x04, 0xc2, 0xe8,
	0x68, 0x8b, 0x03, 0x6f, 0x72, 0x66, 0x02, 0x61, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x1e, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x03,
}

var tcpDnsData = dnsData{
	question: "orf.at",
	answers: []dnsRecord{
		{uint32(dnsmessage.TypeA), "orf.at", "194.232.104.149"},
		{uint32(dnsmessage.TypeA), "orf.at", "194.232.104.140"},
		{uint32(dnsmessage.TypeA), "orf.at", "194.232.104.139"},
		{uint32(dnsmessage.TypeA), "orf.at", "194.232.104.3"},
		{uint32(dnsmessage.TypeA), "orf.at", "194.232.104.4"},
		{uint32(dnsmessage.TypeA), "orf.at", "194.232.104.142"},
		{uint32(dnsmessage.TypeA), "orf.at", "194.232.104.150"},
		{uint32(dnsmessage.TypeA), "orf.at", "194.232.104.141"},
	},
}
var dnsOverTCP4FullMessage = []byte{
	// IP header
	0x45, 0x00, 0x00, 0xd9, 0x1f, 0x80, 0x00, 0x00, 0x3e, 0x06, 0x40, 0xca, 0x08, 0x08, 0x08, 0x08,
	0x0a, 0xf4, 0x00, 0xd2,

	// TCP header
	0x00, 0x35, 0x8c, 0xa3, 0x68, 0x44, 0x89, 0x14, 0xf6, 0xbc, 0xee, 0x75, 0x80, 0x18, 0x10, 0x00,
	0xde, 0x52, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x9c, 0x9f, 0xf4, 0x2a, 0xaa, 0xaa, 0x20, 0x0d,

	// DNS length
	0x00, 0xa3,

	// DNS message
	0xbb, 0xcb, 0x81, 0x80, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x03, 0x6f, 0x72, 0x66,
	0x02, 0x61, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
	0x3f, 0xd1, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x95, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
	0x3f, 0xd1, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x8c, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
	0x3f, 0xd1, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x8b, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
	0x3f, 0xd1, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x03, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
	0x3f, 0xd1, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x04, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
	0x3f, 0xd1, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x8e, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
	0x3f, 0xd1, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x96, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
	0x3f, 0xd1, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x8d, 0x00, 0x00, 0x29, 0x02, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00,
}

// NOTE: both the IP header checksum and TCP checksum are invalid, but since we are not useing them
// anyway, it doesn't matter for the test.
var dnsOverTCP4Partial = []byte{
	0x0a, 0xf4, 0x00, 0xd2,

	// TCP header
	0x00, 0x35, 0x8c, 0xa3, 0x68, 0x44, 0x89, 0x14, 0xf6, 0xbc, 0xee, 0x75, 0x80, 0x18, 0x10, 0x00,
	0xde, 0x52, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x9c, 0x9f, 0xf4, 0x2a, 0xaa, 0xaa, 0x20, 0x0d,

	// DNS length
	0x00, 0xa0,

	// DNS message
	0xbb, 0xcb, 0x81, 0x80, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x03, 0x6f, 0x72, 0x66,
	0x02, 0x61, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
	0x3f, 0xd1, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x95, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
	0x3f, 0xd1, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x8c, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
	0x3f, 0xd1, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x8b, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
	0x3f, 0xd1, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x03, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
	0x3f, 0xd1, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x04, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
	0x3f, 0xd1, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x8e, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
	0x3f, 0xd1, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x96, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
	0x3f, 0xd1, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x8d, 0x00, 0x00, 0x29, 0x02, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00,
}

func TestDecodeDns(t *testing.T) {
	type testCase struct {
		title       string
		data        []byte
		expectError bool
		expectedDns dnsData
	}

	testCases := []testCase{
		{
			title:       "udp",
			data:        dnsOverUDP4,
			expectedDns: udpDnsData,
		},
		{
			title:       "tcp full message",
			data:        dnsOverTCP4FullMessage,
			expectedDns: tcpDnsData,
		},
		{
			title:       "tcp partial message",
			data:        dnsOverTCP4Partial,
			expectError: true,
		},
	}

	var d layers.DNS
	for _, test := range testCases {
		t.Run(test.title, func(t *testing.T) {
			result, err := decodeDNS(test.data, &d)
			if test.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			require.Equal(t, test.expectedDns.question, result.GetDNSQuestionDomain())
			require.Len(t, result.GetAnswers(), len(test.expectedDns.answers))

			for i, answer := range result.GetAnswers() {
				expectedAnswer := test.expectedDns.answers[i]

				require.Equal(t, expectedAnswer.dnsType, answer.Type)
				require.Equal(t, expectedAnswer.name, answer.Name)
				resIP, _ := netip.AddrFromSlice(answer.Ip)
				require.Equal(t, expectedAnswer.ip, resIP.String())
			}
		})
	}
}

func BenchmarkDNSDecode(b *testing.B) {
	b.Run("custom-gopacket", func(b *testing.B) {
		b.ReportAllocs()
		var dnsParser layers.DNS
		for i := 0; i < b.N; i++ {
			_, err := decodeDNS(dnsOverUDP4, &dnsParser)
			if err != nil {
				fmt.Println(err)
				b.FailNow()
			}
		}
	})

	b.Run("gopacket", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := decodeDNSGoPacket(dnsOverUDP4)
			if err != nil {
				fmt.Println(err)
				b.FailNow()
			}
		}
	})
}

func decodeDNSGoPacket(data []byte) (*castpb.DNS, error) {
	payload, _, err := packet.ExtractPayload(data)
	if err != nil {
		return nil, err
	}

	var d layers.DNS
	if err := d.DecodeFromBytes(payload, nil); err != nil {
		return nil, err
	}

	pbDNS := &castpb.DNS{
		Answers: make([]*castpb.DNSAnswers, len(d.Answers)),
	}

	for _, v := range d.Questions {
		pbDNS.DNSQuestionDomain = string(v.Name)
		break
	}

	for i, v := range d.Answers {
		pbDNS.Answers[i] = &castpb.DNSAnswers{
			Name:  string(v.Name),
			Type:  uint32(v.Type),
			Class: uint32(v.Class),
			Ttl:   v.TTL,
			Ip:    v.IP,
			Cname: string(v.CNAME),
		}
	}

	return pbDNS, nil
}
