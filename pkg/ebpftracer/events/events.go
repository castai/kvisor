package events

const (
	Sys32Undefined ID = 0xfffffff - 1 // u32 overflows are compiler implementation dependent.
	Undefined      ID = 0xfffffff
	Unsupported    ID = 10000
)

type ID uint32

// NOTE: Events should match defined values in ebpf code.

// Common events (used by all architectures).
const (
	NetPacketBase ID = iota + 700
	NetPacketIPBase
	NetPacketTCPBase
	NetPacketUDPBase
	NetPacketICMPBase
	NetPacketICMPv6Base
	NetPacketDNSBase
	NetPacketSOCKS5Base
	NetPacketSSHBase
	NetFlowBase
	MaxNetID // network base events go ABOVE this item

	SysEnter
	SysExit
	SchedProcessFork
	SchedProcessExec
	SchedProcessExit
	SchedSwitch
	MagicWrite
	CgroupMkdir
	CgroupRmdir
	SecurityBprmCheck
	SecuritySocketConnect
	SocketDup
	FileModification
	SockSetState
	ProcessOomKilled
	TtyOpen
	TtyWrite
	StdioViaSocket
	MaxCommonID
)

// Special events for stats aggregations and metrics.
const (
	TrackSyscallStats ID = iota + 4100
)

// Signature events
const (
	StartSignatureID ID = iota + 6000
	MaxSignatureID   ID = 6999
)

const (
	TestEvent ID = 9999
)
