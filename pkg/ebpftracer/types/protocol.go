package types

import (
	"github.com/castai/kvisor/pkg/ebpftracer/events"
)

// BinType is an enum that specifies the type of binary data sent in the file perf map
// binary types should match defined values in ebpf code
type BinType uint8

const (
	SendVfsWrite BinType = iota + 1
	SendMprotect
	SendKernelModule
	SendBpfObject
	SendVfsRead
)

// PLEASE NOTE, YOU MUST UPDATE THE DECODER IF ANY CHANGE TO THIS STRUCT IS DONE.

// EventContext struct contains common metadata that is collected for all types of events
// it is used to unmarshal binary data and therefore should match (bit by bit) to the `context_t` struct in the ebpf code.
type EventContext struct {
	Ts        uint64
	StartTime uint64 `sourceField:"Task.StartTime"`
	CgroupID  uint64 `sourceField:"Task.CgroupId"`
	Pid       uint32 `sourceField:"Task.Pid"`
	Tid       uint32 `sourceField:"Task.Tid"`
	Ppid      uint32 `sourceField:"Task.Ppid"`
	HostPid   uint32 `sourceField:"Task.HostPid"`
	HostTid   uint32 `sourceField:"Task.HostTid"`
	HostPpid  uint32 `sourceField:"Task.HostPpid"`
	// PID translated to PIDNS the container runtime is running in
	NodeHostPid     uint32    `sourceField:"Task.NodeHostPid"`
	Uid             uint32    `sourceField:"Task.Uid"`
	MntID           uint32    `sourceField:"Task.MntId"`
	PidID           uint32    `sourceField:"Task.PidId"`
	Comm            [16]byte  `sourceField:"Task.Comm"`
	LeaderStartTime uint64    `sourceField:"Task.LeaderStartTime"`
	ParentStartTime uint64    `sourceField:"Task.ParentStartTime"`
	EventID         events.ID `sourceField:"Eventid"`
	Syscall         int32
	Retval          int64
	ProcessorId     uint16
}

func (ctx *EventContext) GetFlowDirection() FlowDirection {
	if ctx.Retval&FlagPacketIngress > 0 && ctx.Retval&FlagPacketEgress > 0 {
		// something is broken if both ingress and egress flags are set
		return FlowDirectionUnknown
	}

	if ctx.Retval&FlagPacketIngress > 0 {
		return FlowDirectionIngress
	}
	if ctx.Retval&FlagPacketEgress > 0 {
		return FlowDirectionEgress
	}

	return FlowDirectionUnknown
}

func (ctx *EventContext) GetNetflowType() NetflowType {
	if ctx.Retval&FlagFlowTCPBegin > 0 {
		return NetflowTypeTCPBegin
	}
	if ctx.Retval&FlagFlowTCPSample > 0 {
		return NetflowTypeTCPSample
	}
	if ctx.Retval&FlagFlowTCPEnd > 0 {
		return NetflowTypeTCPEnd
	}
	return NetflowTypeUnknown
}

func (ctx *EventContext) IsSourceInitiator() bool {
	return ctx.Retval&FlagFlowSrcInitiator > 0
}

const (
	FlagFamilyIPv4 int64 = (1 << 0)
	FlagFamilyIPv6       = (1 << 1)
	// HTTP Direction (request/response) Flag
	FlagProtoHTTPReq  = (1 << 2)
	FlagProtoHTTPResp = (1 << 3)
	// Packet Direction (ingress/egress) Flag
	FlagPacketIngress = (1 << 4)
	FlagPacketEgress  = (1 << 5)
	// Flows (begin/end) Flags per Protocol
	FlagFlowTCPBegin     = (1 << 6)  // syn+ack flag or first flow packet
	FlagFlowTCPSample    = (1 << 7)  // tcp flow sample
	FlagFlowTCPEnd       = (1 << 8)  // fin flag or last flow packet
	FlagFlowUDPBegin     = (1 << 9)  // first flow packet
	FlagFlowUDPEnd       = (1 << 10) // last flow packet
	FlagFlowSrcInitiator = (1 << 11) // src is the flow initiator
)
