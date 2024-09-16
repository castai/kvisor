package ebpftracer

import (
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type probeType uint8

const (
	kProbe = iota
	kretProbe
	tracepoint
	rawTracepoint
	btfTracepoint
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
	case btfTracepoint:
		probeLink, err = link.AttachTracing(link.TracingOptions{
			Program:    p.program,
			AttachType: ebpf.AttachTraceRawTp,
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
	ProbeVfsWriteMagic
	ProbeVfsWriteMagicRet
	ProbeVfsWriteVMagic
	ProbeVfsWriteVMagicRet
	ProbeKernelWriteMagic
	ProbeKernelWriteMagicRet
	ProbeCgroupMkdir
	ProbeCgroupRmdir
	ProbeSecurityBPRMCheck
	ProbeSecuritySocketConnect
	ProbeLoadElfPhdrs
	ProbeCgroupSKBIngress
	ProbeCgroupSKBEgress
	ProbeFileUpdateTime
	ProbeFileUpdateTimeRet
	ProbeFileModified
	ProbeFileModifiedRet
	ProbeFdInstall
	ProbeFilpClose
	ProbeExecBinprm
	ProbeInetSockSetState
	ProbeOomMarkVictim
	ProbeTtyOpen
	ProbeTtyWrite
	ProbeCgroupSockCreate
)

func newProbes(objs *tracerObjects, cgroupPath string) map[handle]probe {
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
		ProbeVfsWriteMagic:          newTraceProbe(kProbe, "vfs_write", objs.VfsWriteMagicEnter),
		ProbeVfsWriteMagicRet:       newTraceProbe(kretProbe, "vfs_write", objs.VfsWriteMagicReturn),
		ProbeVfsWriteVMagic:         newTraceProbe(kProbe, "vfs_writev", objs.VfsWritevMagicEnter),
		ProbeVfsWriteVMagicRet:      newTraceProbe(kretProbe, "vfs_writev", objs.VfsWritevMagicReturn),
		ProbeKernelWriteMagic:       newTraceProbe(kProbe, "__kernel_write", objs.KernelWriteMagicEnter),
		ProbeKernelWriteMagicRet:    newTraceProbe(kretProbe, "__kernel_write", objs.KernelWriteMagicReturn),
		ProbeCgroupMkdir:            newTraceProbe(rawTracepoint, "cgroup:cgroup_mkdir", objs.TracepointCgroupCgroupMkdir),
		ProbeCgroupRmdir:            newTraceProbe(rawTracepoint, "cgroup:cgroup_rmdir", objs.TracepointCgroupCgroupRmdir),
		ProbeSecurityBPRMCheck:      newTraceProbe(kProbe, "security_bprm_check", objs.TraceSecurityBprmCheck),
		ProbeSecuritySocketConnect:  newTraceProbe(kProbe, "security_socket_connect", objs.TraceSecuritySocketConnect),
		ProbeLoadElfPhdrs:           newTraceProbe(kProbe, "load_elf_phdrs", objs.TraceLoadElfPhdrs),
		ProbeCgroupSKBIngress:       newCgroupProbe(ebpf.AttachCGroupInetIngress, cgroupPath, objs.CgroupSkbIngress),
		ProbeCgroupSKBEgress:        newCgroupProbe(ebpf.AttachCGroupInetEgress, cgroupPath, objs.CgroupSkbEgress),
		ProbeFileUpdateTime:         newTraceProbe(kProbe, "file_update_time", objs.TraceFileUpdateTime),
		ProbeFileUpdateTimeRet:      newTraceProbe(kretProbe, "file_update_time", objs.TraceRetFileUpdateTime),
		ProbeFileModified:           newTraceProbe(kProbe, "file_modified", objs.TraceFileModified),
		ProbeFileModifiedRet:        newTraceProbe(kretProbe, "file_modified", objs.TraceRetFileUpdateTime),
		ProbeFdInstall:              newTraceProbe(kProbe, "fd_install", objs.TraceFdInstall),
		ProbeFilpClose:              newTraceProbe(kProbe, "filp_close", objs.TraceFilpClose),
		ProbeExecBinprm:             newTraceProbe(kProbe, "exec_binprm", objs.TraceExecBinprm),
		ProbeInetSockSetState:       newTraceProbe(btfTracepoint, "sock:inet_sock_set_state", objs.TraceInetSockSetState),
		ProbeOomMarkVictim:          newTraceProbe(rawTracepoint, "oom:mark_victim", objs.OomMarkVictim),
		ProbeTtyOpen:                newTraceProbe(kProbe, "tty_open", objs.TtyOpen),
		ProbeTtyWrite:               newTraceProbe(kProbe, "tty_write", objs.TtyWrite),
		ProbeCgroupSockCreate:       newCgroupProbe(ebpf.AttachCGroupInetSockCreate, cgroupPath, objs.CgroupSockCreate),
	}
}
