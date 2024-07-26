package proc

import (
	"bytes"
	"cmp"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/castai/kvisor/pkg/system"
)

type Process struct {
	PID  PID
	PPID PID
	Args []string
	// StartTime since boot start
	StartTime time.Duration
	FilePath  string
}

// SnapshotProcessTree records a snappshot of the current process tree in the PID namespace of the
// given targetPID. This is done by iterating over files exposed from the `/proc` filesystem.
func (p *Proc) SnapshotProcessTree(targetPID PID) ([]Process, error) {
	targetPIDString := pidToString(targetPID)
	targetPath := filepath.Join(targetPIDString, "root", "proc")

	entries, err := p.procFS.ReadDir(targetPath)
	if err != nil {
		return nil, err
	}

	// This will always overshoot with memory, but still better than not pre-allocating.
	processes := make([]Process, 0, len(entries))

	for _, de := range entries {
		// We only care about processes, hence we test for numbers only folders.
		if !de.IsDir() || !numOnlyName(de.Name()) {
			continue
		}

		pid, err := parsePID(de.Name())
		if err != nil {
			return nil, err
		}

		if pid == 2 {
			// PID 2 will always be kthreadd, which we do not care about.
			continue
		}

		data, err := p.procFS.ReadFile(
			filepath.Join(targetPath, pidToString(pid), "stat"))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				// A process can exit after we got the dir list. In such cases, we simply ignore it.
				continue
			}
			return nil, err
		}

		statData, err := getDataFromStat(data)
		if err != nil {
			return nil, err
		}

		if statData.PPID == 2 {
			// All processes under PID 2 (kthreadd) are kernel threads we do not want to display
			continue
		}

		processStartTime := system.TicksToDuration(statData.StartTime)

		// The symlink will be relative to the container root, so this should work just fine. Sadly symlink-support for FS is not merged
		// into go yet, hence we need to fall back to Readlink.
		path, err := os.Readlink(filepath.Join(Path, targetPath, pidToString(pid), "exe"))
		if err != nil {
			// TODO(patrick.pichler): Figure out what to do on error
			path = ""
		}

		var cmdLine []string
		data, err = p.procFS.ReadFile(
			filepath.Join(targetPath, pidToString(pid), "cmdline"))
		// A process can exit after we got the dir list. Do not mess up the process tree, we will still report the process.
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		} else {
			cmdLine = parseCmdline(data)
		}

		processes = append(processes, Process{
			PID:       pid,
			PPID:      statData.PPID,
			Args:      cmdLine,
			StartTime: processStartTime,
			FilePath:  path,
		})
	}

	slices.SortFunc(processes, func(a, b Process) int {
		return cmp.Compare(a.PID, b.PID)
	})

	return processes, nil
}

func parseCmdline(data []byte) []string {
	result := strings.Split(string(data), "\x00")

	// We need to cut the last element, since data will end with a NULL byte,
	// causing the last element always to be empty.
	return result[0 : len(result)-1]
}

func pidToString(pid PID) string {
	return strconv.FormatUint(uint64(pid), 10)
}

type processTreeData struct {
	PPID PID
	// StartTime is measured in ticks since host start.
	StartTime uint64
}

func getDataFromStat(data []byte) (processTreeData, error) {
	commEndIndex := bytes.Index(data, []byte{')', ' '})
	if commEndIndex < 0 {
		return processTreeData{}, ErrParseStatFileInvalidCommFormat
	}

	// According to https://man7.org/linux/man-pages/man5/proc.5.html , the PPID is the 4 field. Since we cut
	// out `comm` (2 field) we need to adjust the index. The -1 is to adjust for zero being the first elements in slices.
	adjustedPPIDIdx := 4 - 2 - 1
	adjustedStartTimeIdx := 22 - 2 - 1

	maxFields := adjustedStartTimeIdx + 1

	fields := bytes.SplitN(data[commEndIndex+2:], []byte{' '}, maxFields+1)
	if len(fields) < maxFields {
		return processTreeData{}, ErrParseStatFileNotEnoughFields
	}
	ppid, err := parsePID(string(fields[adjustedPPIDIdx]))
	if err != nil {
		return processTreeData{}, err
	}
	startTime, err := strconv.ParseUint(string(fields[adjustedStartTimeIdx]), 10, 64)
	if err != nil {
		return processTreeData{}, err
	}

	return processTreeData{
		PPID:      ppid,
		StartTime: startTime,
	}, nil
}

func numOnlyName(name string) bool {
	for _, r := range name {
		if r < '0' || r > '9' {
			return false
		}
	}

	return true
}
