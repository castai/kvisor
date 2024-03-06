package types

import (
	"net/netip"

	"github.com/castai/kvisor/pkg/containers"
)

type Event struct {
	Context   *EventContext
	Container *containers.Container
	Args      Args
}

type AddrTuple struct {
	Src netip.AddrPort
	Dst netip.AddrPort
}
