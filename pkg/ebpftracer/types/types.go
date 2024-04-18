package types

import (
	"net/netip"

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
	FlowDirectionIncoming
	FlowDirectionOutgoing
)
