package pipeline

import (
	"net/netip"
)

type clusterInfo struct {
	podCidr     []netip.Prefix
	serviceCidr []netip.Prefix
}

func (c *clusterInfo) podCidrContains(ip netip.Addr) bool {
	for _, cidr := range c.podCidr {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func (c *clusterInfo) serviceCidrContains(ip netip.Addr) bool {
	for _, cidr := range c.serviceCidr {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}
