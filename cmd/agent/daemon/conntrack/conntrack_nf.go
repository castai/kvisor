package conntrack

import (
	"net"
	"net/netip"
	"strings"
	"syscall"

	"github.com/castai/logging"
	"github.com/florianl/go-conntrack"
	"github.com/samber/lo"
)

type NetfilterConntrackClient struct {
	log  *logging.Logger
	nfct *conntrack.Nfct
}

func (n *NetfilterConntrackClient) GetDestination(src, dst netip.AddrPort) (netip.AddrPort, bool) {
	// TODO(Kvisor): Track metrics and consider adding LRU hashmap cache if we make to many syscalls.

	req := conntrack.Con{
		Origin: &conntrack.IPTuple{
			Src: lo.ToPtr(net.IP(src.Addr().AsSlice())),
			Dst: lo.ToPtr(net.IP(dst.Addr().AsSlice())),
			Proto: &conntrack.ProtoTuple{
				Number:  lo.ToPtr(uint8(syscall.IPPROTO_TCP)),
				SrcPort: lo.ToPtr(src.Port()),
				DstPort: lo.ToPtr(dst.Port()),
			},
		},
	}
	family := conntrack.IPv4
	if dst.Addr().Is6() {
		family = conntrack.IPv6
	}
	sessions, err := n.nfct.Get(conntrack.Conntrack, family, req)
	if err != nil {
		if !strings.Contains(err.Error(), "no such file or directory") {
			n.log.Errorf("getting conntrack records: %v", err)
		}
		return netip.AddrPort{}, false
	}
	for _, sess := range sessions {
		if !isTupleValid(sess.Reply) {
			continue
		}
		ip, ok := netip.AddrFromSlice(*sess.Reply.Src)
		if !ok {
			continue
		}
		res := netip.AddrPortFrom(ip, *sess.Reply.Proto.SrcPort)
		return res, true
	}
	return netip.AddrPort{}, false
}

func (n *NetfilterConntrackClient) Close() error {
	return n.nfct.Close()
}

func isTupleValid(t *conntrack.IPTuple) bool {
	if t == nil {
		return false
	}
	if t.Src == nil || t.Dst == nil || t.Proto == nil {
		return false
	}
	if t.Proto.SrcPort == nil || t.Proto.DstPort == nil {
		return false
	}
	return true
}
