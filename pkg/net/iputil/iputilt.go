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
