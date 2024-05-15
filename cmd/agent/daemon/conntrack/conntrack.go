package conntrack

import (
	"net/netip"
	"os"

	"github.com/castai/kvisor/pkg/logging"
	"github.com/florianl/go-conntrack"
	"github.com/vishvananda/netns"

	stdlog "log"
)

type Client interface {
	GetDestination(src, dst netip.AddrPort) (netip.AddrPort, bool)
	Close() error
}

func NewClient(log *logging.Logger) (Client, error) {
	if iniCiliumMaps(log) {
		return &CiliumConntrack{}, nil
	}

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
