package types

import "net/netip"

type SockAddrFamily int16

const (
	AF_UNSPEC     SockAddrFamily = 0
	AF_UNIX       SockAddrFamily = 1
	AF_LOCAL      SockAddrFamily = AF_UNIX
	AF_INET       SockAddrFamily = 2
	AF_AX25       SockAddrFamily = 3
	AF_IPX        SockAddrFamily = 4
	AF_APPLETALK  SockAddrFamily = 5
	AF_NETROM     SockAddrFamily = 6
	AF_BRIDGE     SockAddrFamily = 7
	AF_ATMPVC     SockAddrFamily = 8
	AF_X25        SockAddrFamily = 9
	AF_INET6      SockAddrFamily = 10
	AF_ROSE       SockAddrFamily = 11
	AF_DECnet     SockAddrFamily = 12
	AF_NETBEUI    SockAddrFamily = 13
	AF_SECURITY   SockAddrFamily = 14
	AF_KEY        SockAddrFamily = 15
	AF_NETLINK    SockAddrFamily = 16
	AF_ROUTE      SockAddrFamily = AF_NETLINK
	AF_PACKET     SockAddrFamily = 17
	AF_ASH        SockAddrFamily = 18
	AF_ECONET     SockAddrFamily = 19
	AF_ATMSVC     SockAddrFamily = 20
	AF_RDS        SockAddrFamily = 21
	AF_SNA        SockAddrFamily = 22
	AF_IRDA       SockAddrFamily = 23
	AF_PPPOX      SockAddrFamily = 24
	AF_WANPIPE    SockAddrFamily = 25
	AF_LLC        SockAddrFamily = 26
	AF_IB         SockAddrFamily = 27
	AF_MPLS       SockAddrFamily = 28
	AF_CAN        SockAddrFamily = 29
	AF_TIPC       SockAddrFamily = 30
	AF_BLUETOOTH  SockAddrFamily = 31
	AF_IUCV       SockAddrFamily = 32
	AF_RXRPC      SockAddrFamily = 33
	AF_ISDN       SockAddrFamily = 34
	AF_PHONET     SockAddrFamily = 35
	AF_IEEE802154 SockAddrFamily = 36
	AF_CAIF       SockAddrFamily = 37
	AF_ALG        SockAddrFamily = 38
	AF_NFC        SockAddrFamily = 39
	AF_VSOCK      SockAddrFamily = 40
	AF_KCM        SockAddrFamily = 41
	AF_QIPCRTR    SockAddrFamily = 42
	AF_SMC        SockAddrFamily = 43
	AF_XDP        SockAddrFamily = 44
)

var sockAddrTypeNames = map[SockAddrFamily]string{
	AF_UNSPEC:     "AF_UNSPEC",
	AF_UNIX:       "AF_UNIX",
	AF_INET:       "AF_INET",
	AF_AX25:       "AF_AX25",
	AF_IPX:        "AF_IPX",
	AF_APPLETALK:  "AF_APPLETALK",
	AF_NETROM:     "AF_NETROM",
	AF_BRIDGE:     "AF_BRIDGE",
	AF_ATMPVC:     "AF_ATMPVC",
	AF_X25:        "AF_X25",
	AF_INET6:      "AF_INET6",
	AF_ROSE:       "AF_ROSE",
	AF_DECnet:     "AF_DECnet",
	AF_NETBEUI:    "AF_NETBEUI",
	AF_SECURITY:   "AF_SECURITY",
	AF_KEY:        "AF_KEY",
	AF_NETLINK:    "AF_NETLINK",
	AF_PACKET:     "AF_PACKET",
	AF_ASH:        "AF_ASH",
	AF_ECONET:     "AF_ECONET",
	AF_ATMSVC:     "AF_ATMSVC",
	AF_RDS:        "AF_RDS",
	AF_SNA:        "AF_SNA",
	AF_IRDA:       "AF_IRDA",
	AF_PPPOX:      "AF_PPPOX",
	AF_WANPIPE:    "AF_WANPIPE",
	AF_LLC:        "AF_LLC",
	AF_IB:         "AF_IB",
	AF_MPLS:       "AF_MPLS",
	AF_CAN:        "AF_CAN",
	AF_TIPC:       "AF_TIPC",
	AF_BLUETOOTH:  "AF_BLUETOOTH",
	AF_IUCV:       "AF_IUCV",
	AF_RXRPC:      "AF_RXRPC",
	AF_ISDN:       "AF_ISDN",
	AF_PHONET:     "AF_PHONET",
	AF_IEEE802154: "AF_IEEE802154",
	AF_CAIF:       "AF_CAIF",
	AF_ALG:        "AF_ALG",
	AF_NFC:        "AF_NFC",
	AF_VSOCK:      "AF_VSOCK",
	AF_KCM:        "AF_KCM",
	AF_QIPCRTR:    "AF_QIPCRTR",
	AF_SMC:        "AF_SMC",
	AF_XDP:        "AF_XDP",
}

func (t SockAddrFamily) String() string {
	if t, found := sockAddrTypeNames[t]; found {
		return t
	}

	return "UNKNOWN"
}

type internalSockAddr struct{}

func (internalSockAddr) sockaddr() {}

type Sockaddr interface {
	sockaddr()

	Family() SockAddrFamily
}

type UnixSockAddr struct {
	internalSockAddr

	Path string
}

func (UnixSockAddr) Family() SockAddrFamily {
	return AF_UNIX
}

type Ip4SockAddr struct {
	internalSockAddr

	Addr netip.AddrPort
}

func (Ip4SockAddr) Family() SockAddrFamily {
	return AF_INET
}

type Ip6SockAddr struct {
	internalSockAddr

	Addr     netip.AddrPort
	FlowInfo uint32
	ScopeID  uint32
}

func (Ip6SockAddr) Family() SockAddrFamily {
	return AF_INET6
}

// GenericSockAddr is a catch all of socket addr family types we do now specifically handle yet
type GenericSockAddr struct {
	internalSockAddr

	family SockAddrFamily
}

func (a GenericSockAddr) Family() SockAddrFamily {
	return a.family
}

func NewGenericSockAddr(family SockAddrFamily) GenericSockAddr {
	return GenericSockAddr{
		family: family,
	}
}
