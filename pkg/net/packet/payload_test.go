package packet

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var icmp4RequestBuffer = []byte{
	// IP header up to checksum
	0x45, 0x00, 0x00, 0x27, 0xde, 0xad, 0x00, 0x00, 0x40, 0x01, 0x8c, 0x15,
	// source IP
	0x01, 0x02, 0x03, 0x04,
	// destination IP
	0x05, 0x06, 0x07, 0x08,
	// ICMP header
	0x08, 0x00, 0x7d, 0x22,
	// "request_payload"
	0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64,
}

var malformedPacketLengthIPv4 = []byte{
	0x45, 0x74, 0x00, 0x00, 0x5f, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64,
}

var malformedPacketInvalidIPVersion = []byte{
	0x25, 0x74, 0x00, 0x00, 0x5f, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64,
}

var tcp4PacketPayload = []byte{
	0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64,
}

var tcp4Packet = []byte{
	// IP header up to checksum
	0x45, 0x00, 0x00, 0x37, 0xde, 0xad, 0x00, 0x00, 0x40, 0x06, 0x49, 0x5f,
	// source IP
	0x01, 0x02, 0x03, 0x04,
	// destination IP
	0x05, 0x06, 0x07, 0x08,
	// TCP header with SYN, ACK set
	0x00, 0x7b, 0x02, 0x37, 0x00, 0x00, 0x12, 0x34, 0x00, 0x00, 0x00, 0x00,
	0x50, 0x12, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
	// "request_payload"
	0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64,
}

var tcp6PacketPayload = []byte{
	0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64,
}

var tcp6Packet = []byte{
	// IPv6 header up to hop limit
	0x60, 0x06, 0xef, 0xcc, 0x00, 0x23, 0x06, 0x40,
	// Src addr
	0x20, 0x01, 0x05, 0x59, 0xbc, 0x13, 0x54, 0x00, 0x17, 0x49, 0x46, 0x28, 0x39, 0x34, 0x0e, 0x1b,
	// Dst addr
	0x26, 0x07, 0xf8, 0xb0, 0x40, 0x0a, 0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x0e,
	// TCP header with SYN, ACK set
	0x00, 0x7b, 0x02, 0x37, 0x00, 0x00, 0x12, 0x34, 0x00, 0x00, 0x00, 0x00,
	0x50, 0x12, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
	// "request_payload"
	0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64,
}

var udp4RequestPayload = []byte{
	0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64,
}

var udp4Request = []byte{
	// IP header up to checksum
	0x45, 0x00, 0x00, 0x2b, 0xde, 0xad, 0x00, 0x00, 0x40, 0x11, 0x8c, 0x01,
	// source IP
	0x01, 0x02, 0x03, 0x04,
	// destination IP
	0x05, 0x06, 0x07, 0x08,
	// UDP header
	0x00, 0x7b, 0x02, 0x37, 0x00, 0x17, 0x72, 0x1d,
	// "request_payload"
	0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64,
}

var udp6RequestPayload = []byte{
	0x5c, 0x06, 0xae, 0x85, 0x02, 0xf5, 0xdb, 0x90, 0xe0, 0xe0, 0x93, 0xed, 0x9a, 0xd9, 0x92, 0x69, 0xbe, 0x36, 0x8a, 0x7d, 0xd7, 0xce, 0xd0, 0x8a, 0xf2, 0x51, 0x95, 0xff, 0xb6, 0x92, 0x70, 0x10, 0xd7,
}

var udp6Request = []byte{
	// IPv6 header up to hop limit
	0x60, 0x0e, 0xc9, 0x67, 0x00, 0x29, 0x11, 0x40,
	// Src addr
	0x20, 0x01, 0x05, 0x59, 0xbc, 0x13, 0x54, 0x00, 0x17, 0x49, 0x46, 0x28, 0x39, 0x34, 0x0e, 0x1b,
	// Dst addr
	0x26, 0x07, 0xf8, 0xb0, 0x40, 0x0a, 0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x0e,
	// UDP header
	0xd4, 0x04, 0x01, 0xbb, 0x00, 0x29, 0x96, 0x84,
	// Payload
	0x5c, 0x06, 0xae, 0x85, 0x02, 0xf5, 0xdb, 0x90, 0xe0, 0xe0, 0x93, 0xed, 0x9a, 0xd9, 0x92, 0x69, 0xbe, 0x36, 0x8a, 0x7d, 0xd7, 0xce, 0xd0, 0x8a, 0xf2, 0x51, 0x95, 0xff, 0xb6, 0x92, 0x70, 0x10, 0xd7,
}

func TestExtractPayload(t *testing.T) {
	type testCase struct {
		title               string
		data                []byte
		expectedError       error
		expectedPayload     []byte
		expectedSubProtocol SubProtocol
	}

	testCases := []testCase{
		{
			title:         "unsupported sub protocol",
			data:          icmp4RequestBuffer,
			expectedError: ErrUnsupportedSubProtocol,
		},
		{
			title:         "malformed ipv4 packet length",
			data:          malformedPacketLengthIPv4,
			expectedError: ErrOffsetBiggerThanData,
		},
		{
			title:         "malformed ip packet unsupported ip version",
			data:          malformedPacketInvalidIPVersion,
			expectedError: ErrUnsupportedIPVersion,
		},
		{
			title:               "ipv4 tcp request",
			data:                tcp4Packet,
			expectedPayload:     tcp4PacketPayload,
			expectedSubProtocol: SubProtocolTCP,
		},
		{
			title:               "ipv4 udp request",
			data:                udp4Request,
			expectedPayload:     udp4RequestPayload,
			expectedSubProtocol: SubProtocolUDP,
		},
		{
			title:               "ipv6 tcp request",
			data:                tcp6Packet,
			expectedPayload:     tcp6PacketPayload,
			expectedSubProtocol: SubProtocolTCP,
		},
		{
			title:               "ipv6 udp request",
			data:                udp6Request,
			expectedPayload:     udp6RequestPayload,
			expectedSubProtocol: SubProtocolUDP,
		},
	}

	for _, test := range testCases {
		t.Run(test.title, func(t *testing.T) {
			payload, subProtocol, err := ExtractPayload(test.data)
			if test.expectedError != nil {
				require.ErrorIs(t, err, test.expectedError)
				require.Equal(t, UnsupportedSubProtocol, subProtocol)
				return
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, test.expectedPayload, payload)
			require.Equal(t, test.expectedSubProtocol, subProtocol)
		})
	}
}

var sinkPayload []byte

func BenchmarkDecode(b *testing.B) {
	type benchmark struct {
		title string
		data  []byte
	}

	benchmarks := []benchmark{
		{
			title: "tcp4",
			data:  tcp4Packet,
		},
		{
			title: "tcp6",
			data:  tcp6Packet,
		},
		{
			title: "udp4",
			data:  udp4Request,
		},
		{
			title: "udp6",
			data:  udp6Request,
		},
	}

	for _, bench := range benchmarks {
		b.Run(bench.title, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				sinkPayload, _, _ = ExtractPayload(bench.data)
			}
		})
	}
}