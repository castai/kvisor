package signature

import (
	"net/netip"

	v1 "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/ebpftracer/events"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/logging"
)

var _ Signature = (*StdioViaSocket)(nil)

type StdioViaSocket struct {
	log *logging.Logger
}

func NewStdViaSocketSignature(log *logging.Logger) Signature {
	return &StdioViaSocket{
		log: log,
	}
}

func (*StdioViaSocket) GetMetadata() SignatureMetadata {
	return SignatureMetadata{
		ID:      v1.SignatureEventID_SIGNATURE_STDIO_VIA_SOCKET,
		Name:    "stdio_via_socket",
		Version: "0.0.1",
		TargetEvents: []events.ID{
			events.SecuritySocketConnect,
			events.SocketDup,
		},
	}
}

func (s *StdioViaSocket) OnEvent(event *types.Event) *v1.SignatureFinding {
	var socketfd int32
	var remoteAddr types.Sockaddr

	switch args := event.Args.(type) {
	case types.SecuritySocketConnectArgs:
		socketfd = args.Sockfd
		remoteAddr = args.RemoteAddr
	case types.SocketDupArgs:
		socketfd = args.Newfd
		remoteAddr = args.RemoteAddr
	default:
		// This case should never happen. If it does, there is nothing we can detect here.
		s.log.Warnf("got unknown arguments type when handling StdioViaSocket for event `%d`", event.Context.EventID)
		return nil
	}

	// This signature only cares about stdio fds
	if socketfd != 0 && socketfd != 1 && socketfd != 2 {
		return nil
	}

	if remoteAddr == nil {
		s.log.Warnf("remoteAddr was nil for event `%d`", event.Context.EventID)
		return nil
	}

	var netaddr netip.AddrPort

	switch addr := remoteAddr.(type) {
	case types.Ip4SockAddr:
		netaddr = addr.Addr
	case types.Ip6SockAddr:
		netaddr = addr.Addr
	default:
		// This signature can only handle IPv4 and IPv6 socket addrs. In the future we might
		// want to think about support other addr types too.
		return nil
	}

	if netaddr.Port() == 0 {
		return nil
	}

	return &v1.SignatureFinding{}
}
