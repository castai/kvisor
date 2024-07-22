package proc

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strconv"
	"strings"
	"syscall"

	"github.com/samber/lo"
)

// Path to proc filesystem.
const Path = "/proc"

func GetFS() ProcFS {
	// DirFS guarantees to return a fs.StatFS, fs.ReadFileFS and fs.ReadDirFS implementation, hence we can simply cast it here
	return os.DirFS("/proc").(ProcFS)
}

type PID = uint32
type NamespaceID = uint64

type NamespaceType string

const (
	PIDNamespace   NamespaceType = "pid"
	MountNamespace NamespaceType = "mnt"
)

type ProcFS interface {
	fs.ReadDirFS
	fs.ReadFileFS
	fs.StatFS
}

var (
	ErrCannotGetPIDNSInode            = errors.New("cannot get pidns inode")
	ErrParseStatFileInvalidCommFormat = errors.New("cannot parse stat file, invalid comm format")
	ErrParseStatFileNotEnoughFields   = errors.New("cannot parse stat file, not enough fields")
	ErrNoCgroupPathFound              = errors.New("no cgroup path found")
)

type Proc struct {
	procFS ProcFS
}

func New() *Proc {
	return &Proc{
		procFS: GetFS(),
	}
}

func NewFromFS(fs ProcFS) *Proc {
	return &Proc{
		procFS: fs,
	}
}

// HostPath returns full file path on the host file system using procfs, eg: /proc/1/root/<my-path>
func HostPath(p string) string {
	return path.Join(Path, strconv.Itoa(1), p)
}

func (p *Proc) FindCGroupPathForPID(pid PID) (string, error) {
	cgroupData, err := p.procFS.ReadFile(fmt.Sprintf("%d/cgroup", pid))
	if err != nil {
		return "", err
	}

	var emptyFallback string

	for _, line := range strings.Split(string(cgroupData), "\n") {
		// Last line will be empty, we simply ignore it.
		if len(line) == 0 {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) < 3 {
			continue
		}
		// TODO: we hardcode this for now, but in the future we might want to make this configurable
		// (cpuset might not always be the first cgroup reported by the kernel)
		if parts[1] == "cpuset" {
			return parts[2], nil
		}

		if parts[1] == "" {
			emptyFallback = parts[2]
		}
	}

	if emptyFallback != "" {
		return emptyFallback, nil
	}

	return "", ErrNoCgroupPathFound
}

func (p *Proc) GetCurrentPIDNSID() (NamespaceID, error) {
	return p.GetNSForPID(1, PIDNamespace)
}

func (p *Proc) LoadMountNSOldestProcesses() (map[NamespaceID]PID, error) {
	files, err := p.procFS.ReadDir(".")
	if err != nil {
		return nil, err
	}

	type processInfo struct {
		pid PID
		age uint64
	}

	namespaceMap := map[NamespaceID]processInfo{}

	for _, f := range files {
		pid, err := parsePID(f.Name())
		if err != nil {
			continue
		}

		mntNS, err := p.GetNSForPID(pid, MountNamespace)
		if err != nil {
			continue
		}

		processAge, err := p.GetProcessStartTime(pid)
		if err != nil {
			continue
		}

		current, found := namespaceMap[mntNS]
		if found {
			if current.age < processAge {
				continue
			}
		}

		namespaceMap[mntNS] = processInfo{
			pid: pid,
			age: processAge,
		}
	}

	return lo.MapValues(namespaceMap, func(value processInfo, key NamespaceID) PID {
		return value.pid
	}), nil
}

func parsePID(pidStr string) (PID, error) {
	pid, err := strconv.ParseUint(pidStr, 10, 32)
	if err != nil {
		return 0, err
	}

	return PID(pid), nil
}

func (p *Proc) GetNSForPID(pid PID, ns NamespaceType) (NamespaceID, error) {
	info, err := p.procFS.Stat(fmt.Sprintf("%d/ns/%s", pid, ns))
	if err != nil {
		return 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, ErrCannotGetPIDNSInode
	}

	return NamespaceID(stat.Ino), nil
}

// GetProcessStartTime parses the /proc/<pid>/stat file to determine the start time of the process after system boot.
func (p *Proc) GetProcessStartTime(pid PID) (uint64, error) {
	data, err := p.procFS.ReadFile(fmt.Sprintf("%d/stat", pid))
	if err != nil {
		return 0, err
	}

	commEndIndex := bytes.Index(data, []byte{')', ' '})
	if commEndIndex < 0 {
		return 0, ErrParseStatFileInvalidCommFormat
	}

	fields := bytes.Split(data[commEndIndex+2:], []byte{' '})
	// According to https://man7.org/linux/man-pages/man5/proc.5.html , the start time is the 22 field. Since we cut
	// out `comm` (2 field) we need to adjust the index. The -1 is to adjust for zero being the first elements in slices.
	adjustedStartTimeIdx := 22 - 2 - 1

	if len(fields) < adjustedStartTimeIdx {
		return 0, ErrParseStatFileNotEnoughFields
	}

	return strconv.ParseUint(string(fields[adjustedStartTimeIdx]), 10, 64)
}
