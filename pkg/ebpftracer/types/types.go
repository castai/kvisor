package types

import (
	"net/netip"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/bucketcache"
	"github.com/castai/kvisor/pkg/containers"
	"github.com/castai/kvisor/pkg/proc"
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

type ProtoDNS = castpb.DNS
type ProtoSSH = castpb.SSHData

type PIDsPerNamespace = bucketcache.BucketCache[proc.NamespaceID, proc.PID]

func namespaceHash(ns proc.NamespaceID) uint32 {
	return uint32(ns)
}

func NewPIDsPerNamespaceCache(size, maxBucketSize uint32) (*PIDsPerNamespace, error) {
	result, err := bucketcache.New[proc.NamespaceID, proc.PID](size, maxBucketSize, namespaceHash)
	if err != nil {
		return nil, err
	}

	return (*PIDsPerNamespace)(result), nil
}

type FlowDirection uint8

const (
	FlowDirectionUnknown FlowDirection = iota
	FlowDirectionIngress
	FlowDirectionEgress
)

var flowDirectionNames = map[FlowDirection]string{
	FlowDirectionIngress: "INGRESS",
	FlowDirectionEgress:  "EGRESS",
}

func (f FlowDirection) String() string {
	if name, found := flowDirectionNames[f]; found {
		return name
	}

	return "UNKNOWN"
}

type NetflowType uint8

const (
	NetflowTypeUnknown NetflowType = iota
	NetflowTypeTCPBegin
	NetflowTypeTCPSample
	NetflowTypeTCPEnd
)

func (f NetflowType) String() string {
	if name, found := flowTypesNames[f]; found {
		return name
	}

	return "UNKNOWN"
}

var flowTypesNames = map[NetflowType]string{
	NetflowTypeTCPBegin:  "TCP_BEGIN",
	NetflowTypeTCPSample: "TCP_SAMPLE",
	NetflowTypeTCPEnd:    "TCP_END",
}
