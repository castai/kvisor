package enrichment

import (
	"context"
	"crypto/rand"
	"path/filepath"
	"strconv"
	"testing"
	"testing/fstest"
	"time"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/containers"
	"github.com/castai/kvisor/pkg/ebpftracer/events"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/castai/kvisor/pkg/proc"
	"github.com/minio/sha256-simd"
	"github.com/stretchr/testify/require"
)

func TestFileHashEnricher(t *testing.T) {
	t.Run("should set sha256 hash of file", func(t *testing.T) {
		r := require.New(t)
		containerID := "12354"
		fileName := "test"
		pid := uint32(22)
		testFile := generateExecutableTestMapFile(2048)
		wantedSum := sha256.Sum256(testFile.Data)
		fsys := fstest.MapFS{
			filepath.Join(strconv.Itoa(int(pid)), "root", fileName): testFile,
		}

		enricher := EnrichWithFileHash(
			logging.New(&logging.Config{}),
			createDummyMntNSPIDStore(0, 10),
			fsys)

		in := &types.Event{
			Context: &types.EventContext{
				EventID:     events.SchedProcessExec,
				NodeHostPid: pid,
			},
			Container: &containers.Container{
				ID: containerID,
			},
			Args: types.SchedProcessExecArgs{
				Filepath: filepath.Join(fileName),
			},
		}

		out := &castpb.ContainerEvent{Data: &castpb.ContainerEvent_Exec{Exec: &castpb.Exec{}}}
		enricher.Enrich(context.TODO(), in, out)

		r.Equal(wantedSum[:], out.GetExec().GetHashSha256())
	})

	t.Run("should ignore missing file", func(t *testing.T) {
		r := require.New(t)
		containerID := "12354"
		fileName := "test"
		fsys := fstest.MapFS{}

		enricher := EnrichWithFileHash(logging.New(&logging.Config{}),
			createDummyMntNSPIDStore(0, 1),
			fsys)

		in := &types.Event{
			Context: &types.EventContext{},
			Container: &containers.Container{
				ID: containerID,
			},
			Args: types.SchedProcessExecArgs{
				Filepath: filepath.Join(fileName),
			},
		}

		out := &castpb.ContainerEvent{Data: &castpb.ContainerEvent_Exec{Exec: &castpb.Exec{}}}
		enricher.Enrich(context.TODO(), in, out)

		r.Empty(out.GetExec().HashSha256)
	})

	t.Run("should ignore non exec event", func(t *testing.T) {
		r := require.New(t)
		containerID := "12354"
		fsys := fstest.MapFS{}

		enricher := EnrichWithFileHash(logging.New(&logging.Config{}),
			createDummyMntNSPIDStore(0, 1),
			fsys)

		in := &types.Event{
			Context: &types.EventContext{},
			Container: &containers.Container{
				ID: containerID,
			},
		}

		out := &castpb.ContainerEvent{Data: &castpb.ContainerEvent_Exec{Exec: &castpb.Exec{}}}
		enricher.Enrich(context.TODO(), in, out)

		r.Nil(out.GetExec().HashSha256)
	})

	t.Run("should set sha256 hash of file for two same events", func(t *testing.T) {
		r := require.New(t)
		containerID := "12354"
		fileName := "test"
		pid := proc.PID(22)
		testFile := generateExecutableTestMapFile(2048)
		wantedSum := sha256.Sum256(testFile.Data)
		fsys := fstest.MapFS{
			filepath.Join(strconv.Itoa(int(pid)), "root", fileName): testFile,
		}

		enricher := EnrichWithFileHash(
			logging.New(&logging.Config{}),
			createDummyMntNSPIDStore(0, pid),
			fsys)

		in := &types.Event{
			Context: &types.EventContext{
				EventID:     events.SchedProcessExec,
				NodeHostPid: pid,
			},
			Container: &containers.Container{
				ID: containerID,
			},
			Args: types.SchedProcessExecArgs{
				Filepath: filepath.Join(fileName),
			},
		}

		out := &castpb.ContainerEvent{Data: &castpb.ContainerEvent_Exec{Exec: &castpb.Exec{}}}
		enricher.Enrich(context.TODO(), in, out)

		r.Equal(wantedSum[:], out.GetExec().GetHashSha256())

		in = &types.Event{
			Context: &types.EventContext{
				EventID:     events.SchedProcessExec,
				NodeHostPid: pid,
			},
			Container: &containers.Container{
				ID: containerID,
			},
			Args: types.SchedProcessExecArgs{
				Filepath: filepath.Join(fileName),
			},
		}

		out = &castpb.ContainerEvent{Data: &castpb.ContainerEvent_Exec{Exec: &castpb.Exec{}}}
		enricher.Enrich(context.TODO(), in, out)
		r.Equal(wantedSum[:], out.GetExec().GetHashSha256())
	})

	t.Run("should fallback to other pids in mount ns if file is missing", func(t *testing.T) {
		r := require.New(t)
		containerID := "12354"
		fileName := "test"
		pid := proc.PID(22)
		mountNSID := proc.NamespaceID(10)
		testFile := generateExecutableTestMapFile(2048)
		wantedSum := sha256.Sum256(testFile.Data)
		fsys := fstest.MapFS{
			filepath.Join(strconv.Itoa(int(pid)), "root", fileName): testFile,
		}

		enricher := EnrichWithFileHash(
			logging.New(&logging.Config{}),
			createDummyMntNSPIDStore(mountNSID, pid),
			fsys)

		in := &types.Event{
			Context: &types.EventContext{
				EventID: events.SchedProcessExec,
				MntID:   uint32(mountNSID),
			},
			Container: &containers.Container{
				ID: containerID,
			},
			Args: types.SchedProcessExecArgs{
				Filepath: filepath.Join(fileName),
			},
		}

		out := &castpb.ContainerEvent{Data: &castpb.ContainerEvent_Exec{Exec: &castpb.Exec{}}}
		enricher.Enrich(context.TODO(), in, out)

		r.Equal(wantedSum[:], out.GetExec().GetHashSha256())
	})
}

func generateTestData(size uint32) []byte {
	result := make([]byte, size)
	rand.Read(result)
	return result
}

func generateExecutableTestMapFile(size uint32) *fstest.MapFile {
	return &fstest.MapFile{
		Data:    generateTestData(size),
		Mode:    0777,
		ModTime: time.Now(),
	}
}

func createDummyMntNSPIDStore(ns proc.NamespaceID, pids ...proc.PID) *types.PIDsPerNamespace {
	b, err := types.NewPIDsPerNamespaceCache(10, 5)
	if err != nil {
		panic(err)
	}

	for _, pid := range pids {
		b.AddToBucket(ns, pid)
	}

	return b
}
