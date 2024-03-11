package enrichment

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"path/filepath"
	"strconv"
	"testing"
	"testing/fstest"
	"time"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/castai/kvisor/pkg/proc"
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

		event := &castpb.Event{
			EventType:   castpb.EventType_EVENT_EXEC,
			ContainerId: containerID,
			Data: &castpb.Event_Exec{
				Exec: &castpb.Exec{
					Path: filepath.Join(fileName),
					Args: []string{},
				},
			},
		}

		enricher.Enrich(context.TODO(), &EnrichRequest{
			Event: event,
			EventContext: &types.EventContext{
				NodeHostPid: pid,
			},
			Args: types.SchedProcessExecArgs{},
		})

		r.Equal(wantedSum[:], event.GetExec().GetMeta().GetHashSha256())
	})

	t.Run("should ignore missing file", func(t *testing.T) {
		r := require.New(t)
		containerID := "12354"
		fileName := "test"
		fsys := fstest.MapFS{}

		enricher := EnrichWithFileHash(logging.New(&logging.Config{}),
			createDummyMntNSPIDStore(0, 1),
			fsys)

		event := &castpb.Event{
			EventType:   castpb.EventType_EVENT_EXEC,
			ContainerId: containerID,
			Data: &castpb.Event_Exec{
				Exec: &castpb.Exec{
					Path: filepath.Join(fileName),
					Args: []string{},
				},
			},
		}

		enricher.Enrich(context.TODO(), &EnrichRequest{
			Event:        event,
			EventContext: &types.EventContext{},
			Args:         types.SchedProcessExecArgs{},
		})

		r.Nil(event.GetExec().Meta)
	})

	t.Run("should ignore non exec event", func(t *testing.T) {
		r := require.New(t)
		containerID := "12354"
		fsys := fstest.MapFS{}

		enricher := EnrichWithFileHash(logging.New(&logging.Config{}),
			createDummyMntNSPIDStore(0, 1),
			fsys)

		event := &castpb.Event{
			EventType:   castpb.EventType_EVENT_DNS,
			ContainerId: containerID,
		}

		enricher.Enrich(context.TODO(), &EnrichRequest{
			Event:        event,
			EventContext: &types.EventContext{},
			Args:         types.SchedProcessExecArgs{},
		})

		r.Nil(event.GetExec())
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

		event := &castpb.Event{
			EventType:   castpb.EventType_EVENT_EXEC,
			ContainerId: containerID,
			Data: &castpb.Event_Exec{
				Exec: &castpb.Exec{
					Path: filepath.Join(fileName),
					Args: []string{},
				},
			},
		}

		enricher.Enrich(context.TODO(), &EnrichRequest{
			Event: event,
			EventContext: &types.EventContext{
				NodeHostPid: pid,
			},
			Args: types.SchedProcessExecArgs{},
		})

		r.Equal(wantedSum[:], event.GetExec().GetMeta().GetHashSha256())

		event = &castpb.Event{
			EventType:   castpb.EventType_EVENT_EXEC,
			ContainerId: containerID,
			Data: &castpb.Event_Exec{
				Exec: &castpb.Exec{
					Path: filepath.Join(fileName),
					Args: []string{},
				},
			},
		}

		enricher.Enrich(context.TODO(), &EnrichRequest{
			Event: event,
			EventContext: &types.EventContext{
				NodeHostPid: pid,
			},
			Args: types.SchedProcessExecArgs{},
		})

		r.Equal(wantedSum[:], event.GetExec().GetMeta().GetHashSha256())
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

		event := &castpb.Event{
			EventType:   castpb.EventType_EVENT_EXEC,
			ContainerId: containerID,
			Data: &castpb.Event_Exec{
				Exec: &castpb.Exec{
					Path: filepath.Join(fileName),
					Args: []string{},
				},
			},
		}

		enricher.Enrich(context.TODO(), &EnrichRequest{
			Event: event,
			EventContext: &types.EventContext{
				MntID: uint32(mountNSID),
			},
			Args: types.SchedProcessExecArgs{},
		})

		r.Equal(wantedSum[:], event.GetExec().GetMeta().GetHashSha256())
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
