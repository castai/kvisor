package state

import (
	"net/netip"
	"time"

	"github.com/castai/kvisor/pkg/ebpftracer/types"
)

type clusterInfo struct {
	podCidr     netip.Prefix
	serviceCidr netip.Prefix
}

type netflowVal struct {
	exportedAt   time.Time
	event        *types.Event
	destinations map[uint64]*netflowDest
}

type netflowDest struct {
	addrPort  netip.AddrPort
	txBytes   uint64
	rxBytes   uint64
	txPackets uint64
	rxPackets uint64
}

func (d *netflowDest) empty() bool {
	return d.rxBytes == 0 && d.txBytes == 0
}
