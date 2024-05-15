//go:build !linux

package conntrack

import (
	"net/netip"

	"github.com/castai/kvisor/pkg/logging"
)

func iniCiliumMaps(log *logging.Logger) bool {
	return false
}

func lookupCiliumConntrackTable(src, dst netip.AddrPort) *netip.AddrPort {
	return nil
}

func closeCilium() {}
