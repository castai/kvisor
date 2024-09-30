package state

import (
	"net/netip"
)

type clusterInfo struct {
	podCidr     netip.Prefix
	serviceCidr netip.Prefix
}
