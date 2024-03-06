package conntrack

import (
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"

	"github.com/castai/kvisor/pkg/logging"
	"github.com/florianl/go-conntrack"
	"github.com/samber/lo"
	"github.com/vishvananda/netns"

	stdlog "log"
)

type Client interface {
	GetDestination(src, dst netip.AddrPort) (netip.AddrPort, bool)
	Close() error
}

func NewClient(log *logging.Logger) (Client, error) {
	// TODO(Kvisord): Add support fo cilium. Read from bpf maps.
	hostNs, err := netns.GetFromPid(1)
	if err != nil {
		return nil, err
	}

	nfct, err := conntrack.Open(&conntrack.Config{
		NetNS:  int(hostNs),
		Logger: stdlog.New(os.Stdout, "nf", 0),
	})

	if err != nil {
		return nil, err
	}
	return &NetfilterConntrackClient{
		log:  log.WithField("component", "nf_conntrack"),
		nfct: nfct,
	}, nil
}

type NetfilterConntrackClient struct {
	log  *logging.Logger
	nfct *conntrack.Nfct
}

func (n *NetfilterConntrackClient) GetDestination(src, dst netip.AddrPort) (netip.AddrPort, bool) {
	// TODO(Kvisord): Track metrics and consider adding LRU hashmap cache if we make to many syscalls.

	//dd, err := n.nfct.Dump(conntrack.Conntrack, conntrack.IPv4)
	//if err != nil {
	//	panic("dump")
	//	return netip.AddrPort{}, false
	//}
	//spew.Dump(dd)
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
