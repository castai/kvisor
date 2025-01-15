package proc

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"syscall"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/cgroup"
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

	return PID(pid), nil // nolint:gosec
}

func (p *Proc) GetNSForPID(pid PID, ns NamespaceType) (NamespaceID, error) {
	info, err := p.procFS.Stat(path.Join(strconv.Itoa(int(pid)), "ns", string(ns)))
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
	data, err := p.procFS.ReadFile(path.Join(strconv.Itoa(int(pid)), "stat"))
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

var psiCheckOnce = sync.OnceValue(func() bool {
	_, err := os.Stat("/proc/pressure/cpu")
	return err == nil
})

func (p *Proc) PSIEnabled() bool {
	return psiCheckOnce()
}

func (*Proc) GetPSIStats(file string) (*castaipb.PSIStats, error) {
	return cgroup.StatPSI("/proc/pressure", file)
}

func (p *Proc) GetMeminfoStats() (*castaipb.MemoryStats, error) {
	f, err := p.procFS.Open("meminfo")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Fields we are interested in.
	var (
		memTotal  uint64
		memFree   uint64
		swapFree  uint64
		swapTotal uint64
	)
	mem := map[string]*uint64{
		"MemTotal":  &memTotal,
		"MemFree":   &memFree,
		"SwapFree":  &swapFree,
		"SwapTotal": &swapTotal,
	}

	found := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), ":", 3)
		if len(parts) != 2 {
			// Should not happen.
			continue
		}
		k := parts[0]
		p, ok := mem[k]
		if !ok {
			// Unknown field -- not interested.
			continue
		}
		vStr := strings.TrimSpace(strings.TrimSuffix(parts[1], " kB"))
		*p, err = strconv.ParseUint(vStr, 10, 64)
		if err != nil {
			return nil, err
		}

		found++
		if found == len(mem) {
			// Got everything we need -- skip the rest.
			break
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	memUsage := memTotal - memFree
	swapUsage := ((swapTotal - swapFree) * 1024) + memUsage

	return &castaipb.MemoryStats{
		Usage: &castaipb.MemoryData{
			Usage: memUsage,
		},
		SwapUsage: &castaipb.MemoryData{
			Usage: swapUsage,
		},
	}, nil
}
