package iputil

import "net/netip"

func IsPrivateNetwork(ip netip.Addr) bool {
	return ip.IsPrivate() ||
		ip.IsLoopback() ||
		ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast()
}

func IsLocalNetwork(ip netip.Addr) bool {
	return ip.IsLoopback() ||
		// https://www.ibm.com/docs/en/zvm/7.2.0?topic=addresses-multicast-scope
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast()
}
