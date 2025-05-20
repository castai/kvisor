package iputil

import (
	"net/netip"
	"testing"
)

func TestIsPrivateNetwork(t *testing.T) {
	testCases := []struct {
		name    string     // Name of the test case.
		ip      netip.Addr // IP address to test.
		want    bool       // Expected result (true if private, false if not).
		wantErr bool       // Expected error status
	}{
		// IPv4 Private Addresses
		{"IPv4 Private 10.0.0.1", netip.MustParseAddr("10.0.0.1"), true, false},
		{"IPv4 Private 10.255.255.254", netip.MustParseAddr("10.255.255.254"), true, false},
		{"IPv4 Private 172.16.0.1", netip.MustParseAddr("172.16.0.1"), true, false},
		{"IPv4 Private 172.31.255.254", netip.MustParseAddr("172.31.255.254"), true, false},
		{"IPv4 Private 192.168.0.1", netip.MustParseAddr("192.168.0.1"), true, false},
		{"IPv4 Private 192.168.255.254", netip.MustParseAddr("192.168.255.254"), true, false},
		{"IPv4 255.255.255.255", netip.MustParseAddr("255.255.255.255"), false, false},

		// IPv4 Loopback Addresses
		{"IPv4 Loopback 127.0.0.1", netip.MustParseAddr("127.0.0.1"), true, false},
		{"IPv4 Loopback 127.255.255.254", netip.MustParseAddr("127.255.255.254"), true, false},

		// IPv4 Multicast Addresses
		{"IPv4 Multicast 224.0.0.1", netip.MustParseAddr("224.0.0.1"), true, false},
		{"IPv4 Multicast 239.255.255.254", netip.MustParseAddr("239.255.255.254"), true, false},

		// IPv4 Link-Local Unicast Addresses
		{"IPv4 Link-Local 169.254.0.1", netip.MustParseAddr("169.254.0.1"), true, false},
		{"IPv4 Link-Local 169.254.255.254", netip.MustParseAddr("169.254.255.254"), true, false},

		// IPv6 Private Addresses
		{"IPv6 Private fd00::1", netip.MustParseAddr("fd00::1"), true, false},
		{"IPv6 Private fc00::1", netip.MustParseAddr("fc00::1"), true, false},

		// IPv6 Loopback Address
		{"IPv6 Loopback ::1", netip.MustParseAddr("::1"), true, false},

		// IPv6 Multicast Addresses
		{"IPv6 Multicast ff00::1", netip.MustParseAddr("ff00::1"), true, false},

		// IPv6 Link-Local Unicast Address
		{"IPv6 Link-Local fe80::1", netip.MustParseAddr("fe80::1"), true, false},

		// IPv6 Link-Local Multicast Address
		{"IPv6 Link-Local Multicast ff02::1", netip.MustParseAddr("ff02::1"), true, false},

		// IPv6 Interface-Local Multicast Address
		{"IPv6 Interface-Local Multicast ff01::1", netip.MustParseAddr("ff01::1"), true, false},

		// Non-Private Addresses (IPv4 and IPv6)
		{"IPv4 0.0.0.0", netip.MustParseAddr("0.0.0.0"), false, false},
		{"IPv4 Public 8.8.8.8", netip.MustParseAddr("8.8.8.8"), false, false},
		{"IPv4 Public 1.1.1.1", netip.MustParseAddr("1.1.1.1"), false, false},
		{"IPv4 Public 172.168.0.10", netip.MustParseAddr("172.168.0.10"), false, false},
		{"IPv6 Public 2001:4860:4860::8888", netip.MustParseAddr("2001:4860:4860::8888"), false, false},
		{"IPv6 Public 2001:4860:4860::8844", netip.MustParseAddr("2001:4860:4860::8844"), false, false},

		// Invalid Address.  Tests that the function handles invalid input correctly.
		{"Invalid IP", netip.Addr{}, false, true}, // netip.Addr{} is the zero value, and is invalid.
	}

	// Iterate over each test case.
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Call the function under test.
			got := IsPrivateNetwork(tc.ip)

			// Check if the result matches the expected value.
			if got != tc.want {
				t.Errorf("IsPrivateNetwork(%v) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}
