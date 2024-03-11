package types

import (
	"fmt"

	"github.com/castai/kvisor/pkg/ebpftracer/events"
	"golang.org/x/sys/unix"
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
// NOTE: Integers want to be aligned in memory, so if changing the format of this struct
// keep the 1-byte 'Argnum' as the final parameter before the padding (if padding is needed).
type EventContext struct {
	Ts        uint64
	StartTime uint64
	CgroupID  uint64
	Pid       uint32
	Tid       uint32
	Ppid      uint32
	HostPid   uint32
	HostTid   uint32
	HostPpid  uint32
	// PID translated to PIDNS the container runtime is running in
	NodeHostPid     uint32
	Uid             uint32
	MntID           uint32
	PidID           uint32
	Comm            [16]byte
	UtsName         [16]byte
	Flags           uint32
	_               [4]byte   // padding
	EventID         events.ID // int32
	Syscall         int32
	MatchedPolicies uint64
	Retval          int64
	StackID         uint32
	ProcessorId     uint16
	_               [2]byte // padding
}

func (EventContext) GetSizeBytes() int {
	return 136
}

type ChunkMeta struct {
	BinType  BinType
	CgroupID uint64
	Metadata [28]byte
	Size     int32
	Off      uint64
}

func (ChunkMeta) GetSizeBytes() uint32 {
	return 49
}

type VfsFileMeta struct {
	DevID uint32
	Inode uint64
	Mode  uint32
	Pid   uint32
}

func (VfsFileMeta) GetSizeBytes() uint32 {
	return 20
}

type KernelModuleMeta struct {
	DevID uint32
	Inode uint64
	Pid   uint32
	Size  uint32
}

func (KernelModuleMeta) GetSizeBytes() uint32 {
	return 20
}

type BpfObjectMeta struct {
	Name [16]byte
	Rand uint32
	Pid  uint32
	Size uint32
}

func (BpfObjectMeta) GetSizeBytes() uint32 {
	return 28
}

type MprotectWriteMeta struct {
	Ts  uint64
	Pid uint32
}

func (MprotectWriteMeta) GetSizeBytes() uint32 {
	return 12
}

// SlimCred struct is a slim version of the kernel's cred struct
// it is used to unmarshal binary data and therefore should match (bit by bit) to the `slim_cred_t` struct in the ebpf code.
// ANY CHANGE TO THIS STRUCT WILL BE REQUIRED ALSO TO detect.SlimCred and bufferdecoder.SlimCred
type SlimCred struct {
	Uid            uint32 /* real UID of the task */
	Gid            uint32 /* real GID of the task */
	Suid           uint32 /* saved UID of the task */
	Sgid           uint32 /* saved GID of the task */
	Euid           uint32 /* effective UID of the task */
	Egid           uint32 /* effective GID of the task */
	Fsuid          uint32 /* UID for VFS ops */
	Fsgid          uint32 /* GID for VFS ops */
	UserNamespace  uint32 /* User Namespace of the of the event */
	SecureBits     uint32 /* SUID-less security management */
	CapInheritable uint64 /* caps our children can inherit */
	CapPermitted   uint64 /* caps we're permitted */
	CapEffective   uint64 /* caps we can actually use */
	CapBounding    uint64 /* capability bounding set */
	CapAmbient     uint64 /* Ambient capability set */
}

func (s SlimCred) GetSizeBytes() uint32 {
	return 80
}

// RawDebugEvent is used to output debug from ebpf to userspace via perf array buf.
type RawDebugEvent struct {
	PID       uint32
	TID       uint32
	Timestamp uint64
	CgroupID  uint64
	Name      [16]byte
	TaskComm  [16]byte
	Arg1      uint64
	Arg2      uint64
	Arg3      uint64
	Arg4      uint64
	//SockAddr  uint64
	//Tuple     rawTuple
}

func (e *RawDebugEvent) String() string {
	args := []any{
		e.Timestamp,
		unix.ByteSliceToString(e.Name[:]),
		e.PID,
		e.CgroupID,
		unix.ByteSliceToString(e.TaskComm[:]),
	}
	tmpl := "DEBUG[%d]: [%s] pid=%d cgroup=%d process=%s"
	if e.Arg1 > 0 {
		tmpl += " arg1=%d"
		args = append(args, e.Arg1)
	}
	if e.Arg2 > 0 {
		tmpl += " arg2=%d"
		args = append(args, e.Arg2)
	}
	if e.Arg3 > 0 {
		tmpl += " arg3=%d"
		args = append(args, e.Arg3)
	}
	if e.Arg4 > 0 {
		tmpl += " arg4=%d"
		args = append(args, e.Arg4)
	}
	//if e.SockAddr > 0 {
	//	tmpl += " sock=%d"
	//	args = append(args, e.SockAddr)
	//
	//	tmpl += " %s -> %s"
	//	src := ipPort(e.Tuple.Family, e.Tuple.Saddr, e.Tuple.Sport)
	//	dst := ipPort(e.Tuple.Family, e.Tuple.Daddr, e.Tuple.Dport)
	//	args = append(args, src, dst)
	//}
	return fmt.Sprintf(tmpl, args...)
}
