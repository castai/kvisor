package proc

import (
	"fmt"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/castai/kvisor/pkg/system"
	"github.com/samber/lo"
	"github.com/stretchr/testify/require"
)

func TestSnapshotProcessTree(t *testing.T) {
	t.Run("load process tree", func(t *testing.T) {
		r := require.New(t)
		entryPID := 99

		procFS := fstest.MapFS{}
		procFS[fmt.Sprintf("%d/root/proc/%d/cmdline", entryPID, 1)] = buildCmdlineFile("service", "--run")
		procFS[fmt.Sprintf("%d/root/proc/%d/stat", entryPID, 1)] = buildStatMapFile(
			StatFileStartTime(99),
			StatFileComm("my-cool-service"),
		)

		procFS[fmt.Sprintf("%d/root/proc/%d/cmdline", entryPID, 100)] = buildCmdlineFile("curl", "cast.ai")
		procFS[fmt.Sprintf("%d/root/proc/%d/stat", entryPID, 100)] = buildStatMapFile(
			StatFileStartTime(200),
			StatFileParentPID(1),
			StatFileComm("curl"),
		)

		procFS[fmt.Sprintf("%d/root/proc/%d/cmdline", entryPID, 104)] = buildCmdlineFile("run_test")
		procFS[fmt.Sprintf("%d/root/proc/%d/stat", entryPID, 104)] = buildStatMapFile(
			StatFileStartTime(100),
			StatFileParentPID(1),
			StatFileComm("run_test"),
		)

		procFS[fmt.Sprintf("%d/root/proc/%d/cmdline", entryPID, 105)] = buildCmdlineFile("test-curl", "--run")
		procFS[fmt.Sprintf("%d/root/proc/%d/stat", entryPID, 105)] = buildStatMapFile(
			StatFileStartTime(150),
			StatFileParentPID(104),
			StatFileComm("test-curl"),
		)

		proc := Proc{procFS: procFS}

		processes, err := proc.SnapshotProcessTree(uint32(entryPID))
		r.NoError(err)
		r.Len(processes, 4)

		lookup := lo.SliceToMap(processes, func(item Process) (PID, Process) {
			return item.PID, item
		})

		root, found := lookup[1]
		r.True(found)
		r.EqualValues(1, root.PID)
		r.EqualValues(0, root.PPID)
		r.EqualValues(system.TicksToDuration(99), root.StartTime)
		r.EqualValues([]string{"service", "--run"}, root.Args)

		process100, found := lookup[100]
		r.True(found)
		r.EqualValues(100, process100.PID)
		r.EqualValues(1, process100.PPID)
		r.EqualValues(system.TicksToDuration(200), process100.StartTime)
		r.EqualValues([]string{"curl", "cast.ai"}, process100.Args)

		process104, found := lookup[104]
		r.True(found)
		r.EqualValues(104, process104.PID)
		r.EqualValues(1, process104.PPID)
		r.EqualValues(system.TicksToDuration(100), process104.StartTime)
		r.EqualValues([]string{"run_test"}, process104.Args)

		process105, found := lookup[105]
		r.True(found)
		r.EqualValues(105, process105.PID)
		r.EqualValues(104, process105.PPID)
		r.EqualValues(system.TicksToDuration(100), process105.StartTime)
		r.EqualValues([]string{"test-curl", "--run"}, process105.Args)
	})
}

func buildCmdlineFile(args ...string) *fstest.MapFile {
	return &fstest.MapFile{
		Data:    []byte(strings.Join(args, "\x00") + "\x00"),
		Mode:    0666,
		ModTime: time.Now(),
	}
}
