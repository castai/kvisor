package state

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/castai/kvisor/pkg/ebpftracer/types"
)

type NetflowGrouping int64

func (n *NetflowGrouping) String() string {
	return fmt.Sprintf("%d", *n)
}

func (n *NetflowGrouping) Set(s string) error {
	v, err := parseNetflowGrouping(s)
	if err != nil {
		return err
	}
	*n = v
	return nil
}

func (n *NetflowGrouping) Type() string {
	return "NetflowGrouping"
}

const (
	NetflowGroupingSrcAddr NetflowGrouping = (1 << iota)
	NetflowGroupingDstAddr
)

var netflowGroupingStrings = map[string]NetflowGrouping{
	"src_addr": NetflowGroupingSrcAddr,
	"dst_addr": NetflowGroupingDstAddr,
}

func parseNetflowGrouping(s string) (NetflowGrouping, error) {
	if s == "" {
		return 0, nil
	}
	var res NetflowGrouping
	for _, flagStr := range strings.Split(s, "|") {
		flag, found := netflowGroupingStrings[flagStr]
		if !found {
			return 0, fmt.Errorf("unknown grouping flag %q", flagStr)
		}
		res |= flag
	}
	return res, nil
}

type clusterInfo struct {
	podCidr     netip.Prefix
	serviceCidr netip.Prefix
}

type netflowVal struct {
	updatedAt    time.Time
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
