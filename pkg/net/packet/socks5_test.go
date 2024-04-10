package packet

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var socks5ClientRequestData = []byte{
	0x05, 0x02, 0x00, 0x01,
}

var socks5ServerMethodSelectData = []byte{
	0x05, 0x00,
}

var socks5ClientConnectRequestIPv4Data = []byte{
	0x05,
	0x01, // connect
	0x00,
	0x01, // IPv4
	// IP data of 142.250.185.99
	0x8e, 0xfa, 0xb9, 0x63,
	// Port 80
	0x00, 0x50,
}

var socks5ClientConnectRequestIPv6Data = []byte{
	0x05,
	0x01, // connect
	0x00,
	0x04, // IPv6
	// IP data of 2001:db8::68
	0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68,
	// Port 80
	0x00, 0x50,
}

var socks5ClientConnectRequestDomainNameData = []byte{
	0x05,
	0x01, // connect
	0x00,
	0x03, // Domainname
	0x07, 'c', 'a', 's', 't', '.', 'a', 'i',
	// Port 80
	0x00, 0x50,
}

var socks5ServerConnectResponseIPv4Data = []byte{
	0x05,
	0x00, // success
	0x00,
	0x01, //IPv4
	// IP data of 10.244.0.22
	0x0a, 0xf4, 0x00, 0x16,
	// Port 52330
	0xcc, 0x6a,
}

var socks5ServerConnectResponseIPv6Data = []byte{
	0x05,
	0x00, // success
	0x00,
	0x04, //IPv6
	// IP data of fe80::0202:b3ff:fe1e:8329
	0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0xb3, 0xff, 0xfe, 0x1e, 0x83, 0x29,
	// Port 52330
	0xcc, 0x6a,
}

func TestParseSOCKS5(t *testing.T) {
	type testCase struct {
		title          string
		payload        []byte
		expectedResult SOCKS5Message
		expectedError  error
	}

	testCases := []testCase{
		{
			title:          "parse client request data message",
			payload:        socks5ClientRequestData,
			expectedResult: SOCKS5InitialClientRequest{},
		},
		{
			title:          "parse server method select message",
			payload:        socks5ServerMethodSelectData,
			expectedResult: SOCKS5InitialServerResponse{},
		},
		{
			title:   "parse client connect ipv4 request",
			payload: socks5ClientConnectRequestIPv4Data,
			expectedResult: SOCKS5RequestOrReply{
				CmdOrReply:  0x01,
				AddressType: SOCKS5AddressTypeIPv4,
				Address:     []byte{0x8e, 0xfa, 0xb9, 0x63},
				Port:        80,
			},
		},
		{
			title:   "parse client connect ipv6 request",
			payload: socks5ClientConnectRequestIPv6Data,
			expectedResult: SOCKS5RequestOrReply{
				CmdOrReply:  0x01,
				AddressType: SOCKS5AddressTypeIPv6,
				Address:     []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68},
				Port:        80,
			},
		},
		{
			title:   "parse client connect domain name request",
			payload: socks5ClientConnectRequestDomainNameData,
			expectedResult: SOCKS5RequestOrReply{
				CmdOrReply:  0x01,
				AddressType: SOCKS5AddressTypeDomainName,
				Address:     []byte("cast.ai"),
				Port:        80,
			},
		},
		{
			title:   "parse server connect ipv4 response",
			payload: socks5ServerConnectResponseIPv4Data,
			expectedResult: SOCKS5RequestOrReply{
				CmdOrReply:  0x00,
				AddressType: SOCKS5AddressTypeIPv4,
				Address:     []byte{0x0a, 0xf4, 0x00, 0x16},
				Port:        52330,
			},
		},
		{
			title:   "parse server connect ipv6 response",
			payload: socks5ServerConnectResponseIPv6Data,
			expectedResult: SOCKS5RequestOrReply{
				CmdOrReply:  0x00,
				AddressType: SOCKS5AddressTypeIPv6,
				Address:     []byte{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0xb3, 0xff, 0xfe, 0x1e, 0x83, 0x29},
				Port:        52330,
			},
		},
		{
			title:         "should fail for payload not starting with 5",
			payload:       []byte{0x01, 0x00},
			expectedError: ErrSOCKS5InvalidVersion,
		},
		{
			title:         "should fail when providing invalid address type",
			payload:       []byte{0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expectedError: ErrSOCKS5InvalidAddressType,
		},
		{
			title:         "should fail when providing invalid message",
			payload:       []byte{0x05, 0x01, 0x04, 0x01},
			expectedError: ErrSOCKS5InvalidMessage,
		},
	}

	for _, test := range testCases {
		t.Run(test.title, func(t *testing.T) {
			r := require.New(t)
			msg, err := ParseSOCKS5(test.payload)
			if test.expectedError != nil {
				r.Error(err)
				r.ErrorIs(err, test.expectedError)
				return
			}

			r.NoError(err)
			r.Equal(test.expectedResult, msg)
		})
	}
}
