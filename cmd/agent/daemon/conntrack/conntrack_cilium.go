package conntrack

import (
	"net/netip"
)

type CiliumConntrack struct {
}

func (c *CiliumConntrack) GetDestination(src, dst netip.AddrPort) (netip.AddrPort, bool) {
	addr := lookupCiliumConntrackTable(src, dst)
	if addr != nil {
		return *addr, true
	}
	return netip.AddrPort{}, false
}

func (c *CiliumConntrack) Close() error {
	closeCilium()
	return nil
}
