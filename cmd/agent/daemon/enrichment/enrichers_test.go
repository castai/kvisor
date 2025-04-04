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

		event := &castpb.ContainerEvent{
			EventType: castpb.EventType_EVENT_EXEC,
			Data: &castpb.ContainerEvent_Exec{
				Exec: &castpb.Exec{
					Path: filepath.Join(fileName),
					Args: []string{},
				},
			},
		}

		enricher.Enrich(context.TODO(), &EnrichedContainerEvent{
			Event: event,
			EbpfEvent: &types.Event{
				Context: &types.EventContext{
					NodeHostPid: pid,
				},
				Args: types.SchedProcessExecArgs{},
			},
		})

		r.Equal(wantedSum[:], event.GetExec().GetHashSha256())

		event1 := &castpb.ContainerEvent{
			EventType: castpb.EventType_EVENT_MAGIC_WRITE,
			Data: &castpb.ContainerEvent_File{
				File: &castpb.File{
					Path: filepath.Join(fileName),
				},
			},
		}

		enricher.Enrich(context.TODO(), &EnrichedContainerEvent{
			Event: event1,
			EbpfEvent: &types.Event{
				Context: &types.EventContext{
					NodeHostPid: pid,
				},
				Args: types.MagicWriteArgs{},
			},
		})

		r.Equal(wantedSum[:], event1.GetFile().GetHashSha256())
	})

	t.Run("should ignore missing file", func(t *testing.T) {
		r := require.New(t)
		fileName := "test"
		fsys := fstest.MapFS{}

		enricher := EnrichWithFileHash(logging.New(&logging.Config{}),
			createDummyMntNSPIDStore(0, 1),
			fsys)

		event := &castpb.ContainerEvent{
			EventType: castpb.EventType_EVENT_EXEC,
			Data: &castpb.ContainerEvent_Exec{
				Exec: &castpb.Exec{
					Path: filepath.Join(fileName),
					Args: []string{},
				},
			},
		}

		enricher.Enrich(context.TODO(), &EnrichedContainerEvent{
			Event: event,
			EbpfEvent: &types.Event{
				Context: &types.EventContext{},
				Args:    types.SchedProcessExecArgs{},
			},
		})

		r.Empty(event.GetExec().HashSha256)
	})

	t.Run("should ignore non exec event", func(t *testing.T) {
		r := require.New(t)
		fsys := fstest.MapFS{}

		enricher := EnrichWithFileHash(logging.New(&logging.Config{}),
			createDummyMntNSPIDStore(0, 1),
			fsys)

		event := &castpb.ContainerEvent{
			EventType: castpb.EventType_EVENT_DNS,
		}

		enricher.Enrich(context.TODO(), &EnrichedContainerEvent{
			Event: event,
			EbpfEvent: &types.Event{
				Context: &types.EventContext{},
				Args:    types.SchedProcessExecArgs{},
			},
		})

		r.Nil(event.GetExec())
	})

	t.Run("should set sha256 hash of file for two same events", func(t *testing.T) {
		r := require.New(t)
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

		event := &castpb.ContainerEvent{
			EventType: castpb.EventType_EVENT_EXEC,
			Data: &castpb.ContainerEvent_Exec{
				Exec: &castpb.Exec{
					Path: filepath.Join(fileName),
					Args: []string{},
				},
			},
		}

		enricher.Enrich(context.TODO(), &EnrichedContainerEvent{
			Event: event,
			EbpfEvent: &types.Event{
				Context: &types.EventContext{
					NodeHostPid: pid,
				},
				Args: types.SchedProcessExecArgs{},
			},
		})

		r.Equal(wantedSum[:], event.GetExec().GetHashSha256())

		event = &castpb.ContainerEvent{
			EventType: castpb.EventType_EVENT_EXEC,
			Data: &castpb.ContainerEvent_Exec{
				Exec: &castpb.Exec{
					Path: filepath.Join(fileName),
					Args: []string{},
				},
			},
		}

		enricher.Enrich(context.TODO(), &EnrichedContainerEvent{
			Event: event,
			EbpfEvent: &types.Event{
				Context: &types.EventContext{
					NodeHostPid: pid,
				},
				Args: types.SchedProcessExecArgs{},
			},
		})

		r.Equal(wantedSum[:], event.GetExec().GetHashSha256())
	})

	t.Run("should fallback to other pids in mount ns if proc folder is missing", func(t *testing.T) {
		r := require.New(t)
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

		event := &castpb.ContainerEvent{
			EventType: castpb.EventType_EVENT_EXEC,
			Data: &castpb.ContainerEvent_Exec{
				Exec: &castpb.Exec{
					Path: filepath.Join(fileName),
					Args: []string{},
				},
			},
		}

		enricher.Enrich(context.TODO(), &EnrichedContainerEvent{
			Event: event,
			EbpfEvent: &types.Event{
				Context: &types.EventContext{
					MntID: uint32(mountNSID),
				},
				Args: types.SchedProcessExecArgs{},
			},
		})

		r.Equal(wantedSum[:], event.GetExec().GetHashSha256())
	})

	t.Run("should fallback to other pids in mount ns if exec path is missing", func(t *testing.T) {
		r := require.New(t)
		fileName := "test"
		rootPid := proc.PID(21)
		pid := proc.PID(22)
		mountNSID := proc.NamespaceID(10)
		testFile := generateExecutableTestMapFile(2048)
		wantedSum := sha256.Sum256(testFile.Data)
		fsys := fstest.MapFS{
			filepath.Join(strconv.Itoa(int(rootPid)), "root", fileName): testFile,
			filepath.Join(strconv.Itoa(int(pid)), "root"):               testFile,
		}

		enricher := EnrichWithFileHash(
			logging.New(&logging.Config{}),
			createDummyMntNSPIDStore(mountNSID, rootPid, pid),
			fsys)

		event := &castpb.ContainerEvent{
			EventType: castpb.EventType_EVENT_EXEC,
			Data: &castpb.ContainerEvent_Exec{
				Exec: &castpb.Exec{
					Path: filepath.Join(fileName),
					Args: []string{},
				},
			},
		}

		enricher.Enrich(context.TODO(), &EnrichedContainerEvent{
			Event: event,
			EbpfEvent: &types.Event{
				Context: &types.EventContext{
					NodeHostPid: pid,
					MntID:       uint32(mountNSID),
				},
				Args: types.SchedProcessExecArgs{},
			},
		})

		r.Equal(wantedSum[:], event.GetExec().GetHashSha256())
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
