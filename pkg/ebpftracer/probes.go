package ebpftracer

import (
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type probeType uint8

const (
	kProbe        = iota // github.com/iovisor/bcc/blob/master/docs/reference_guide.md#1-kp
	kretProbe            // github.com/iovisor/bcc/blob/master/docs/reference_guide.md#1-kp
	tracepoint           // github.com/iovisor/bcc/blob/master/docs/reference_guide.md#3-tracep
	rawTracepoint        // github.com/iovisor/bcc/blob/master/docs/reference_guide.md#7-raw-tracep
)

type probe interface {
	attach() error
	detach() error
	String() string
}

func newTraceProbe(probeType probeType, eventName string, program *ebpf.Program) probe {
	return &traceProbe{
		eventName: eventName,
		probeType: probeType,
		program:   program,
	}
}

type traceProbe struct {
	eventName string
	program   *ebpf.Program
	probeType probeType

	probeLink link.Link
}

func (p *traceProbe) String() string {
	return p.program.String()
}

func (p *traceProbe) attach() error {
	if p.probeLink != nil {
		return nil
	}

	var probeLink link.Link
	var err error
	switch p.probeType {
	case kProbe:
		probeLink, err = link.Kprobe(p.eventName, p.program, nil)
	case kretProbe:
		probeLink, err = link.Kretprobe(p.eventName, p.program, nil)
	case tracepoint:
		tp := strings.Split(p.eventName, ":")
		tpClass := tp[0]
		tpEvent := tp[1]
		probeLink, err = link.Tracepoint(tpClass, tpEvent, p.program, nil)
	case rawTracepoint:
		tpEvent := strings.Split(p.eventName, ":")[1]
		probeLink, err = link.AttachRawTracepoint(link.RawTracepointOptions{
			Name:    tpEvent,
			Program: p.program,
		})
	}
	if err != nil {
		return err
	}
	p.probeLink = probeLink
	return nil
}

func (p *traceProbe) detach() error {
	if p.probeLink == nil {
		return nil
	}
	if err := p.probeLink.Close(); err != nil {
		return err
	}
	p.probeLink = nil
	return nil
}

func newCgroupProbe(probeType ebpf.AttachType, cgroupPath string, program *ebpf.Program) probe {
	return &cgroupProbe{
		cgroupPath: cgroupPath,
		probeType:  probeType,
		program:    program,
	}
}

type cgroupProbe struct {
	cgroupPath string
	program    *ebpf.Program
	probeType  ebpf.AttachType

	probeLink link.Link
}

func (p *cgroupProbe) String() string {
	return p.program.String()
}

func (p *cgroupProbe) attach() error {
	if p.probeLink != nil {
		return nil
	}

	probeLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    p.cgroupPath,
		Attach:  p.probeType,
		Program: p.program,
	})
	if err != nil {
		return err
	}
	p.probeLink = probeLink
	return nil
}

func (p *cgroupProbe) detach() error {
	if p.probeLink == nil {
		return nil
	}
	if err := p.probeLink.Close(); err != nil {
		return err
	}
	p.probeLink = nil
	return nil
}

type handle int32

const (
	ProbeSysEnter handle = iota
	ProbeSysExit
	ProbeSyscallEnter__Internal
	ProbeSyscallExit__Internal
	ProbeSchedProcessFork
	ProbeSchedProcessExec
	ProbeSchedProcessExit
	ProbeSchedProcessFree
	ProbeSchedSwitch
	ProbeDoExit
	ProbeCapCapable
	ProbeVfsWrite
	ProbeVfsWriteRet
	ProbeVfsWriteV
	ProbeVfsWriteVRet
	ProbeSecurityMmapAddr
	ProbeSecurityMmapFile
	ProbeSecurityFileMProtect
	ProbeCommitCreds
	ProbeSwitchTaskNS
	ProbeKernelWrite
	ProbeKernelWriteRet
	ProbeCgroupAttachTask
	ProbeCgroupMkdir
	ProbeCgroupRmdir
	ProbeSecurityBPRMCheck
	ProbeSecurityFileOpen
	ProbeSecurityInodeUnlink
	ProbeSecurityInodeMknod
	ProbeSecurityInodeSymlink
	ProbeSecuritySocketCreate
	ProbeSecuritySocketListen
	ProbeSecuritySocketConnect
	ProbeSecuritySocketAccept
	ProbeSecuritySocketBind
	ProbeSecuritySocketSetsockopt
	ProbeSecuritySbMount
	ProbeSecurityBPF
	ProbeSecurityBPFMap
	ProbeSecurityKernelReadFile
	ProbeSecurityKernelPostReadFile
	ProbeDoSplice
	ProbeDoSpliceRet
	ProbeProcCreate
	ProbeRegisterKprobe
	ProbeRegisterKprobeRet
	ProbeCallUsermodeHelper
	ProbeDebugfsCreateFile
	ProbeDebugfsCreateDir
	ProbeDeviceAdd
	ProbeRegisterChrdev
	ProbeRegisterChrdevRet
	ProbeDoInitModule
	ProbeDoInitModuleRet
	ProbeLoadElfPhdrs
	ProbeFilldir64
	ProbeSecurityFilePermission
	ProbeTaskRename
	ProbePrintSyscallTable
	ProbePrintNetSeqOps
	ProbeSecurityInodeRename
	ProbeDoSigaction
	ProbeSecurityBpfProg
	ProbeSecurityFileIoctl
	ProbeCheckHelperCall
	ProbeCheckMapFuncCompatibility
	ProbeKallsymsLookupName
	ProbeKallsymsLookupNameRet
	ProbeSockAllocFile
	ProbeSockAllocFileRet
	ProbeSecuritySkClone
	ProbeSecuritySocketRecvmsg
	ProbeSecuritySocketSendmsg
	ProbeCgroupBPFRunFilterSKB
	ProbeCgroupSKBIngress
	ProbeCgroupSKBEgress
	ProbeDoMmap
	ProbeDoMmapRet
	ProbePrintMemDump
	ProbeVfsRead
	ProbeVfsReadRet
	ProbeVfsReadV
	ProbeVfsReadVRet
	ProbeVfsUtimes
	ProbeUtimesCommon
	ProbeDoTruncate
	ProbeFileUpdateTime
	ProbeFileUpdateTimeRet
	ProbeFileModified
	ProbeFileModifiedRet
	ProbeFdInstall
	ProbeFilpClose
	ProbeInotifyFindInode
	ProbeInotifyFindInodeRet
	ProbeBpfCheck
	ProbeExecBinprm
	ProbeExecBinprmRet
	ProbeHiddenKernelModuleSeeker
	ProbeTpProbeRegPrioMayExist
	ProbeHiddenKernelModuleVerifier
	ProbeModuleLoad
	ProbeModuleFree
	ProbeLayoutAndAllocate
	ProbeInetSockSetState
	ProbeOomMarkVictim
	ProbeTtyOpen

	// Signal probes
	SignalCgroupMkdir
	SignalCgroupRmdir
)

func newProbes(objs *tracerObjects, cgroupPath string) map[handle]probe {
	//binaryPath := "/proc/self/exe"
	return map[handle]probe{
		ProbeSysEnter:               newTraceProbe(rawTracepoint, "raw_syscalls:sys_enter", objs.TraceSysEnter),
		ProbeSyscallEnter__Internal: newTraceProbe(rawTracepoint, "raw_syscalls:sys_enter", objs.TracepointRawSyscallsSysEnter),
		ProbeSysExit:                newTraceProbe(rawTracepoint, "raw_syscalls:sys_exit", objs.TraceSysExit),
		ProbeSyscallExit__Internal:  newTraceProbe(rawTracepoint, "raw_syscalls:sys_exit", objs.TracepointRawSyscallsSysExit),
		ProbeSchedProcessFork:       newTraceProbe(rawTracepoint, "sched:sched_process_fork", objs.TracepointSchedSchedProcessFork),
		ProbeSchedProcessExec:       newTraceProbe(rawTracepoint, "sched:sched_process_exec", objs.TracepointSchedSchedProcessExec),
		ProbeSchedProcessExit:       newTraceProbe(rawTracepoint, "sched:sched_process_exit", objs.TracepointSchedSchedProcessExit),
		ProbeSchedProcessFree:       newTraceProbe(rawTracepoint, "sched:sched_process_free", objs.TracepointSchedSchedProcessFree),
		ProbeSchedSwitch:            newTraceProbe(rawTracepoint, "sched:sched_switch", objs.TracepointSchedSchedSwitch),
		ProbeDoExit:                 newTraceProbe(kProbe, "do_exit", objs.TraceDoExit),
		ProbeCapCapable:             newTraceProbe(kProbe, "cap_capable", objs.TraceCapCapable),
		ProbeVfsWrite:               newTraceProbe(kProbe, "vfs_write", objs.TraceVfsWrite),
		ProbeVfsWriteRet:            newTraceProbe(kretProbe, "vfs_write", objs.TraceRetVfsWrite),
		ProbeVfsWriteV:              newTraceProbe(kProbe, "vfs_writev", objs.TraceVfsWritev),
		ProbeVfsWriteVRet:           newTraceProbe(kretProbe, "vfs_writev", objs.TraceVfsWritev),
		ProbeKernelWrite:            newTraceProbe(kProbe, "__kernel_write", objs.TraceKernelWrite),
		ProbeKernelWriteRet:         newTraceProbe(kretProbe, "__kernel_write", objs.TraceRetKernelWrite),
		ProbeCgroupAttachTask:       newTraceProbe(rawTracepoint, "cgroup:cgroup_attach_task", objs.TracepointCgroupCgroupAttachTask),
		ProbeCgroupMkdir:            newTraceProbe(rawTracepoint, "cgroup:cgroup_mkdir", objs.TracepointCgroupCgroupMkdir),
		ProbeCgroupRmdir:            newTraceProbe(rawTracepoint, "cgroup:cgroup_rmdir", objs.TracepointCgroupCgroupRmdir),
		ProbeSecurityBPRMCheck:      newTraceProbe(kProbe, "security_bprm_check", objs.TraceSecurityBprmCheck),
		ProbeSecurityFileOpen:       newTraceProbe(kProbe, "security_file_open", objs.TraceSecurityFileOpen),
		//ProbeSecurityFilePermission: newTraceProbe(kProbe, "security_file_permission", objs.TraceSecurityFilePermission),
		ProbeSecuritySocketCreate:  newTraceProbe(kProbe, "security_socket_create", objs.TraceSecuritySocketCreate),
		ProbeSecuritySocketListen:  newTraceProbe(kProbe, "security_socket_listen", objs.TraceSecuritySocketListen),
		ProbeSecuritySocketConnect: newTraceProbe(kProbe, "security_socket_connect", objs.TraceSecuritySocketConnect),
		ProbeSecuritySocketAccept:  newTraceProbe(kProbe, "security_socket_accept", objs.TraceSecuritySocketAccept),
		//ProbeSecuritySocketBind:          NewTraceProbe(kProbe, "security_socket_bind", "trace_security_socket_bind"),
		//ProbeSecuritySocketSetsockopt:    NewTraceProbe(kProbe, "security_socket_setsockopt", "trace_security_socket_setsockopt"),
		//ProbeSecuritySbMount:             NewTraceProbe(kProbe, "security_sb_mount", "trace_security_sb_mount"),
		//ProbeSecurityBPF:                 NewTraceProbe(kProbe, "security_bpf", "trace_security_bpf"),
		//ProbeSecurityBPFMap:              NewTraceProbe(kProbe, "security_bpf_map", "trace_security_bpf_map"),
		//ProbeSecurityKernelReadFile:      NewTraceProbe(kProbe, "security_kernel_read_file", "trace_security_kernel_read_file"),
		//ProbeSecurityKernelPostReadFile:  NewTraceProbe(kProbe, "security_kernel_post_read_file", "trace_security_kernel_post_read_file"),
		//ProbeSecurityInodeMknod:          NewTraceProbe(kProbe, "security_inode_mknod", "trace_security_inode_mknod"),
		//ProbeSecurityInodeSymlink:        NewTraceProbe(kProbe, "security_inode_symlink", "trace_security_inode_symlink"),
		//ProbeSecurityInodeUnlink:         NewTraceProbe(kProbe, "security_inode_unlink", "trace_security_inode_unlink"),
		//ProbeSecurityMmapAddr:            NewTraceProbe(kProbe, "security_mmap_addr", "trace_mmap_alert"),
		//ProbeSecurityMmapFile:            NewTraceProbe(kProbe, "security_mmap_file", "trace_security_mmap_file"),
		//ProbeDoSplice:                    NewTraceProbe(kProbe, "do_splice", "trace_do_splice"),
		//ProbeDoSpliceRet:                 NewTraceProbe(kretProbe, "do_splice", "trace_ret_do_splice"),
		//ProbeProcCreate:                  NewTraceProbe(kProbe, "proc_create", "trace_proc_create"),
		//ProbeSecurityFileMProtect:        NewTraceProbe(kProbe, "security_file_mprotect", "trace_security_file_mprotect"),
		//ProbeCommitCreds:                 NewTraceProbe(kProbe, "commit_creds", "trace_commit_creds"),
		//ProbeSwitchTaskNS:                NewTraceProbe(kProbe, "switch_task_namespaces", "trace_switch_task_namespaces"),
		//ProbeRegisterKprobe:              NewTraceProbe(kProbe, "register_kprobe", "trace_register_kprobe"),
		//ProbeRegisterKprobeRet:           NewTraceProbe(kretProbe, "register_kprobe", "trace_ret_register_kprobe"),
		//ProbeCallUsermodeHelper:          NewTraceProbe(kProbe, "call_usermodehelper", "trace_call_usermodehelper"),
		//ProbeDebugfsCreateFile:           NewTraceProbe(kProbe, "debugfs_create_file", "trace_debugfs_create_file"),
		//ProbeDebugfsCreateDir:            NewTraceProbe(kProbe, "debugfs_create_dir", "trace_debugfs_create_dir"),
		//ProbeDeviceAdd:                   NewTraceProbe(kProbe, "device_add", "trace_device_add"),
		//ProbeRegisterChrdev:              NewTraceProbe(kProbe, "__register_chrdev", "trace___register_chrdev"),
		//ProbeRegisterChrdevRet:           NewTraceProbe(kretProbe, "__register_chrdev", "trace_ret__register_chrdev"),
		//ProbeDoInitModule:                NewTraceProbe(kProbe, "do_init_module", "trace_do_init_module"),
		//ProbeDoInitModuleRet:             NewTraceProbe(kretProbe, "do_init_module", "trace_ret_do_init_module"),
		ProbeLoadElfPhdrs: newTraceProbe(kProbe, "load_elf_phdrs", objs.TraceLoadElfPhdrs),
		//ProbeFilldir64:                   NewTraceProbe(kProbe, "filldir64", "trace_filldir64"),
		//ProbeTaskRename:                  NewTraceProbe(rawTracepoint, "task:task_rename", "tracepoint__task__task_rename"),
		//ProbePrintSyscallTable:           NewUprobe("print_syscall_table", "uprobe_syscall_trigger", binaryPath, "github.com/aquasecurity/tracee/pkg/ebpf.(*Tracee).triggerSyscallsIntegrityCheckCall"),
		//ProbeHiddenKernelModuleSeeker:    NewUprobe("hidden_kernel_module", "uprobe_lkm_seeker", binaryPath, "github.com/aquasecurity/tracee/pkg/ebpf.(*Tracee).triggerKernelModuleSeeker"),
		//ProbeHiddenKernelModuleVerifier:  NewUprobe("hidden_kernel_module", "uprobe_lkm_seeker_submitter", binaryPath, "github.com/aquasecurity/tracee/pkg/ebpf.(*Tracee).triggerKernelModuleSubmitter"),
		//ProbePrintNetSeqOps:              NewUprobe("print_net_seq_ops", "uprobe_seq_ops_trigger", binaryPath, "github.com/aquasecurity/tracee/pkg/ebpf.(*Tracee).triggerSeqOpsIntegrityCheckCall"),
		//ProbePrintMemDump:                NewUprobe("print_mem_dump", "uprobe_mem_dump_trigger", binaryPath, "github.com/aquasecurity/tracee/pkg/ebpf.(*Tracee).triggerMemDumpCall"),
		//ProbeSecurityInodeRename:         NewTraceProbe(kProbe, "security_inode_rename", "trace_security_inode_rename"),
		//ProbeDoSigaction:                 NewTraceProbe(kProbe, "do_sigaction", "trace_do_sigaction"),
		//ProbeSecurityBpfProg:             NewTraceProbe(kProbe, "security_bpf_prog", "trace_security_bpf_prog"),
		//ProbeSecurityFileIoctl:           NewTraceProbe(kProbe, "security_file_ioctl", "trace_security_file_ioctl"),
		//ProbeCheckHelperCall:             NewTraceProbe(kProbe, "check_helper_call", "trace_check_helper_call"),
		//ProbeCheckMapFuncCompatibility:   NewTraceProbe(kProbe, "check_map_func_compatibility", "trace_check_map_func_compatibility"),
		//ProbeKallsymsLookupName:          NewTraceProbe(kProbe, "kallsyms_lookup_name", "trace_kallsyms_lookup_name"),
		//ProbeKallsymsLookupNameRet:       NewTraceProbe(kretProbe, "kallsyms_lookup_name", "trace_ret_kallsyms_lookup_name"),
		ProbeSockAllocFile:         newTraceProbe(kProbe, "sock_alloc_file", objs.TraceSockAllocFile),
		ProbeSockAllocFileRet:      newTraceProbe(kretProbe, "sock_alloc_file", objs.TraceRetSockAllocFile),
		ProbeSecuritySkClone:       newTraceProbe(kProbe, "security_sk_clone", objs.TraceSecuritySkClone),
		ProbeSecuritySocketSendmsg: newTraceProbe(kProbe, "security_socket_sendmsg", objs.TraceSecuritySocketSendmsg),
		ProbeSecuritySocketRecvmsg: newTraceProbe(kProbe, "security_socket_recvmsg", objs.TraceSecuritySocketRecvmsg),
		ProbeCgroupBPFRunFilterSKB: newTraceProbe(kProbe, "__cgroup_bpf_run_filter_skb", objs.CgroupBpfRunFilterSkb),
		ProbeCgroupSKBIngress:      newCgroupProbe(ebpf.AttachCGroupInetIngress, cgroupPath, objs.CgroupSkbIngress),
		ProbeCgroupSKBEgress:       newCgroupProbe(ebpf.AttachCGroupInetEgress, cgroupPath, objs.CgroupSkbEgress),
		//ProbeDoMmap:                      NewTraceProbe(kProbe, "do_mmap", "trace_do_mmap"),
		//ProbeDoMmapRet:                   NewTraceProbe(kretProbe, "do_mmap", "trace_ret_do_mmap"),
		//ProbeVfsRead:                     NewTraceProbe(kProbe, "vfs_read", "trace_vfs_read"),
		//ProbeVfsReadRet:                  NewTraceProbe(kretProbe, "vfs_read", "trace_ret_vfs_read"),
		//ProbeVfsReadV:                    NewTraceProbe(kProbe, "vfs_readv", "trace_vfs_readv"),
		//ProbeVfsReadVRet:                 NewTraceProbe(kretProbe, "vfs_readv", "trace_ret_vfs_readv"),
		//ProbeVfsUtimes:                   NewTraceProbe(kProbe, "vfs_utimes", "trace_vfs_utimes"),
		//ProbeUtimesCommon:                NewTraceProbe(kProbe, "utimes_common", "trace_utimes_common"),
		//ProbeDoTruncate:                  NewTraceProbe(kProbe, "do_truncate", "trace_do_truncate"),
		ProbeFileUpdateTime:    newTraceProbe(kProbe, "file_update_time", objs.TraceFileUpdateTime),
		ProbeFileUpdateTimeRet: newTraceProbe(kretProbe, "file_update_time", objs.TraceRetFileUpdateTime),
		ProbeFileModified:      newTraceProbe(kProbe, "file_modified", objs.TraceFileModified),
		ProbeFileModifiedRet:   newTraceProbe(kretProbe, "file_modified", objs.TraceRetFileUpdateTime),
		ProbeFdInstall:         newTraceProbe(kProbe, "fd_install", objs.TraceFdInstall),
		ProbeFilpClose:         newTraceProbe(kProbe, "filp_close", objs.TraceFilpClose),
		//ProbeInotifyFindInode:            NewTraceProbe(kProbe, "inotify_find_inode", "trace_inotify_find_inode"),
		//ProbeInotifyFindInodeRet:         NewTraceProbe(kretProbe, "inotify_find_inode", "trace_ret_inotify_find_inode"),
		//ProbeBpfCheck:                    NewTraceProbe(kProbe, "bpf_check", "trace_bpf_check"),
		//ProbeExecBinprm:                  NewTraceProbe(kProbe, "exec_binprm", "trace_exec_binprm"),
		//ProbeExecBinprmRet:               NewTraceProbe(kretProbe, "exec_binprm", "trace_ret_exec_binprm"),
		//ProbeTpProbeRegPrioMayExist:      NewTraceProbe(kProbe, "tracepoint_probe_register_prio_may_exist", "trace_tracepoint_probe_register_prio_may_exist"),
		//ProbeModuleLoad:                  NewTraceProbe(rawTracepoint, "module:module_load", "tracepoint__module__module_load"),
		//ProbeModuleFree:                  NewTraceProbe(rawTracepoint, "module:module_free", "tracepoint__module__module_free"),
		//ProbeLayoutAndAllocate:           NewTraceProbe(kretProbe, "layout_and_allocate", "trace_ret_layout_and_allocate"),
		ProbeInetSockSetState: newTraceProbe(rawTracepoint, "sock:inet_sock_set_state", objs.TraceInetSockSetState),
		ProbeOomMarkVictim:    newTraceProbe(rawTracepoint, "oom:mark_victim", objs.OomMarkVictim),
		ProbeTtyOpen:         newTraceProbe(kProbe, "tty_open", objs.TtyOpen),

		// Signal probes
		SignalCgroupMkdir: newTraceProbe(rawTracepoint, "cgroup:cgroup_mkdir", objs.CgroupMkdirSignal),
		SignalCgroupRmdir: newTraceProbe(rawTracepoint, "cgroup:cgroup_rmdir", objs.CgroupRmdirSignal),
	}
}
