package enrichment

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"path/filepath"
	"strconv"
	"syscall"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/metrics"
	"github.com/castai/kvisor/pkg/containers"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/proc"
	"github.com/castai/logging"
	"github.com/cespare/xxhash/v2"
	"github.com/elastic/go-freelru"
	"github.com/minio/sha256-simd"
)

const (
	fileHashEnricherName = "file_hash"
)

type fileHashCacheKey string
type ContainerForCgroupGetter func(cgroup uint64) (*containers.Container, bool, error)
type PIDsInNamespaceGetter func(ns uint32) []uint32

// more hash function in https://github.com/elastic/go-freelru/blob/main/bench/hash.go
func hashStringXXHASH(s fileHashCacheKey) uint32 {
	return uint32(xxhash.Sum64String(string(s))) // nolint:gosec
}

func EnrichWithFileHash(log *logging.Logger, mountNamespacePIDStore *types.PIDsPerNamespace, procFS proc.ProcFS) EventEnricher {
	cache, err := freelru.NewSynced[fileHashCacheKey, []byte](1024, hashStringXXHASH)
	if err != nil {
		// This case can never happen, as err is only thrown if cache size is <0, which it isn't.
		panic(err)
	}

	return &fileHashEnricher{
		log:                    log,
		mountNamespacePIDStore: mountNamespacePIDStore,
		procFS:                 procFS,
		cache:                  cache,
	}
}

type fileHashEnricher struct {
	log                    *logging.Logger
	mountNamespacePIDStore *types.PIDsPerNamespace
	procFS                 fs.StatFS
	cache                  freelru.Cache[fileHashCacheKey, []byte]
}

func (enricher *fileHashEnricher) EventTypes() []castpb.EventType {
	return []castpb.EventType{
		castpb.EventType_EVENT_EXEC,
		castpb.EventType_EVENT_MAGIC_WRITE,
	}
}

func (enricher *fileHashEnricher) getHash(event *types.Event, path string) ([]byte, error) {
	enrichMetric := metrics.AgentEnricherEventsTotalEnriched.WithLabelValues(fileHashEnricherName)
	enrichProcMissingMetric := metrics.AgentFileHashEnricherProcMissingTotal
	enrichErrorMetric := metrics.AgentEnricherEventsTotalErrors.WithLabelValues(fileHashEnricherName)

	sha, err := enricher.calcFileHashForPID(event.Container, proc.PID(event.Context.NodeHostPid), path)
	if err == nil {
		enrichMetric.Inc()
		return sha, nil
	}
	enrichProcMissingMetric.Inc()

	// We always fall back to find the file in the other PIDs of the same mount namespace when the file is not found
	// in the PID of the event, this helps reducing the amount of empty hashes for short-lived processes
	for _, pid := range enricher.mountNamespacePIDStore.GetBucket(proc.NamespaceID(event.Context.MntID)) {
		if pid == proc.PID(event.Context.NodeHostPid) {
			// We already tried that PID of the event, skipping.
			continue
		}

		sha, err := enricher.calcFileHashForPID(event.Container, pid, path)
		// We search for the first PID we can successfully calculate a filehash for.
		if err != nil {
			if errors.Is(err, ErrFileDoesNotExist) {
				// If the wanted file does not exist in the PID mount namespace, it will also not exist in the mounts of the other.
				// We can hence simply return, as we will not find the wanted file.
				enrichErrorMetric.Inc()
				return nil, err
			}
			continue
		}

		enrichMetric.Inc()
		return sha, nil
	}

	enrichErrorMetric.Inc()
	return nil, ErrFileDoesNotExist
}

func (enricher *fileHashEnricher) Enrich(ctx context.Context, req *EnrichedContainerEvent) {
	e := req.Event

	exec := e.GetExec()
	if exec.GetPath() != "" {
		hash, err := enricher.getHash(req.EbpfEvent, exec.Path)
		if err == nil {
			exec.HashSha256 = hash
		}
		return
	}

	file := e.GetFile()
	if file.GetPath() != "" {
		hash, err := enricher.getHash(req.EbpfEvent, file.Path)
		if err == nil {
			file.HashSha256 = hash
		}
		return
	}

}

func (enricher *fileHashEnricher) calcFileHashForPID(cont *containers.Container, pid proc.PID, execPath string) ([]byte, error) {
	pidString := strconv.FormatInt(int64(pid), 10)

	_, err := enricher.procFS.Stat(pidString)
	if err != nil {
		// If the /proc/<pid> folder doesn't exist, there is nothing we can do.
		return nil, ErrProcFolderDoesNotExist
	}

	path := filepath.Join(pidString, "root", execPath)
	info, err := enricher.procFS.Stat(path)
	if err != nil {
		// If the file exec path doesn't exist, there is nothing we can do
		return nil, ErrFileDoesNotExist
	}

	key := enricher.buildCacheKey(cont, info)
	hash, found := enricher.checkCache(key)
	if found {
		return hash, nil
	}

	f, err := enricher.procFS.Open(path)
	if err != nil {
		return nil, ErrFileDoesNotExist
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	hash = h.Sum(nil)
	enricher.cacheHash(key, hash)

	return hash, nil
}

var (
	ErrCannotGetInode         = errors.New("cannot get inode for path")
	ErrProcFolderDoesNotExist = errors.New("/proc/<pid> folder does not exist")
	ErrFileDoesNotExist       = errors.New("wanted file does not exist")
)

func (enricher *fileHashEnricher) buildCacheKey(cont *containers.Container, info fs.FileInfo) fileHashCacheKey {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}

	return fileHashCacheKey(cont.Cgroup.ContainerID + strconv.Itoa(int(stat.Ino))) //nolint:gosec
}

func (enricher *fileHashEnricher) checkCache(key fileHashCacheKey) ([]byte, bool) {
	if key == "" {
		// An empty key indicates an error when calculating the hash key, hence we treat it as not cached.
		return nil, false
	}

	return enricher.cache.Get(key)
}

func (enricher *fileHashEnricher) cacheHash(key fileHashCacheKey, hash []byte) {
	if key == "" {
		// An empty key indicates an error when calculating the hash key, hence nothing will be cached
		return
	}

	enricher.cache.Add(key, hash)
}
