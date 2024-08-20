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
	NetPacketHTTPBase
	NetPacketSOCKS5Base
	NetPacketCapture
	NetCaptureBase
	NetFlowBase
	MaxNetID // network base events go ABOVE this item
	SysEnter
	SysExit
	SchedProcessFork
	SchedProcessExec
	SchedProcessExit
	SchedSwitch
	DoExit
	CapCapable
	VfsWrite
	VfsWritev
	VfsRead
	VfsReadv
	MemProtAlert
	CommitCreds
	SwitchTaskNS
	MagicWrite
	CgroupAttachTask
	CgroupMkdir
	CgroupRmdir
	SecurityBprmCheck
	SecurityFileOpen
	SecurityInodeUnlink
	SecuritySocketCreate
	SecuritySocketListen
	SecuritySocketConnect
	SecuritySocketAccept
	SecuritySocketBind
	SecuritySocketSetsockopt
	SecuritySbMount
	SecurityBPF
	SecurityBPFMap
	SecurityKernelReadFile
	SecurityInodeMknod
	SecurityPostReadFile
	SecurityInodeSymlinkEventId
	SecurityMmapFile
	SecurityFileMprotect
	SocketDup
	HiddenInodes
	KernelWrite
	ProcCreate
	KprobeAttach
	CallUsermodeHelper
	DirtyPipeSplice
	DebugfsCreateFile
	PrintSyscallTable
	DebugfsCreateDir
	DeviceAdd
	RegisterChrdev
	SharedObjectLoaded
	DoInitModule
	SocketAccept
	LoadElfPhdrs
	HookedProcFops
	PrintNetSeqOps
	TaskRename
	SecurityInodeRename
	DoSigaction
	BpfAttach
	KallsymsLookupName
	DoMmap
	PrintMemDump
	VfsUtimes
	DoTruncate
	FileModification
	InotifyWatch
	SecurityBpfProg
	ProcessExecuteFailed
	SecurityPathNotify
	HiddenKernelModuleSeeker
	ModuleLoad
	ModuleFree
	SockSetState
	ProcessOomKilled
	TtyOpen
	TtyWrite
	StdioViaSocket
	MaxCommonID
)

// Events originated from user-space
const (
	NetPacketIPv4 ID = iota + 2000
	NetPacketIPv6
	NetPacketTCP
	NetPacketUDP
	NetPacketICMP
	NetPacketICMPv6
	NetPacketDNS
	NetPacketDNSRequest
	NetPacketDNSResponse
	NetPacketHTTP
	NetPacketHTTPRequest
	NetPacketHTTPResponse
	MaxUserNetID
	InitNamespaces
	ContainerCreate
	ContainerRemove
	ExistingContainer
	HookedSyscalls
	HookedSeqOps
	SymbolsLoaded
	SymbolsCollision
	HiddenKernelModule
	MaxUserSpace
)

// Capture meta-events
const (
	CaptureFileWrite ID = iota + 4000
	CaptureExec
	CaptureModule
	CaptureMem
	CapturePcap
	CaptureNetPacket
	CaptureBpf
	CaptureFileRead
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
