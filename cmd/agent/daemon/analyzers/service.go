package analyzers

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/castai/kvisor/pkg/metrics"
	lru "github.com/hashicorp/golang-lru/v2"
)

// TODO(patrick.pichler): This might be migrated over to a signature
type Config struct {
	ContainersBasePath string
	MinFileSizeBytes   int64
	WorkerCount        int
}

func NewService(log *logging.Logger, cfg Config) *Service {
	return &Service{
		log: log.WithField("component", "analyzers_service"),
		cfg: cfg,
		analyzers: []Analyzer{
			NewGoBinaryAnalyzer(),
			NewElfBinaryAnalyzer(),
		},
		eventsQueue:          make(chan *castpb.Event, 1000),
		outQueue:             make(chan *castpb.Event, 1000),
		containerRemoveQueue: make(chan string, 100),
		cache:                newContainersPathsCache(),
	}
}

type Service struct {
	log                  *logging.Logger
	analyzers            []Analyzer
	eventsQueue          chan *castpb.Event
	outQueue             chan *castpb.Event
	containerRemoveQueue chan string
	cfg                  Config

	cache *containersPathsCache
}

func (s *Service) Enqueue(e *castpb.Event) {
	select {
	case s.eventsQueue <- e:
	default:
		metrics.AgentAnalyzersQueueDroppedEventsTotal.Inc()
	}
}

func (s *Service) Results() <-chan *castpb.Event {
	return s.outQueue
}

func (s *Service) Run(ctx context.Context) error {
	s.log.Infof("running, workers=%d", s.cfg.WorkerCount)
	defer s.log.Infof("stopping")

	// Events processing workers loops.
	for i := 0; i < s.cfg.WorkerCount; i++ {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case e := <-s.eventsQueue:
					s.processEvent(e)
				}
			}
		}()
	}

	// Cache remove loop.
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case cgroupID := <-s.containerRemoveQueue:
			s.cache.delete(cgroupID)
		}
	}
}

func (s *Service) processEvent(e *castpb.Event) {
	execEvent := e.GetExec()

	// We only care about exec events
	if execEvent == nil {
		return
	}

	key := containerFilePath{
		containerID: e.ContainerId,
		filePath:    execEvent.Path,
	}
	if s.cache.containsPath(e.ContainerId, key) {
		return
	}

	res, _ := s.analyzePath(key)
	s.cache.savePath(e.ContainerId, key)
	if res != nil && res.Lang != castpb.Language_LANG_UNKNOWN {
		execEvent.Meta = &castpb.ExecMetadata{
			Lang:      res.Lang,
			Libraries: res.Libraries,
		}
		s.outQueue <- e
	}
}

func (s *Service) analyzePath(path containerFilePath) (*AnalyzerResult, error) {
	hostPath := filepath.Join(s.cfg.ContainersBasePath, path.containerID, "rootfs", path.filePath)
	f, err := os.Open(hostPath)
	if err != nil {
		return nil, err
	}
	fileInfo, err := f.Stat()
	if err != nil {
		return nil, err
	}
	sizeBytes := fileInfo.Size()
	if sizeBytes < s.cfg.MinFileSizeBytes {
		return &AnalyzerResult{}, nil
	}

	start := time.Now()
	defer func() {
		s.log.Debugf("analyzer finished in %v, path=%s, cont=%s", time.Since(start), path.filePath, path.containerID)
	}()

	for _, a := range s.analyzers {
		res, err := a.Analyze(f)
		if err != nil {
			// Do not go to next analyzer if there are no results.
			// This means that current analyzer was able to parse binary.
			if errors.Is(err, errAnalyzerNoResult) {
				return &AnalyzerResult{}, nil
			}
			continue
		}
		metrics.AgentAnalyzersProcessedTotal.Inc()
		if res != nil {
			return res, nil
		}
	}
	return &AnalyzerResult{}, nil
}

func (s *Service) QueueContainerRemove(containerID string) {
	s.containerRemoveQueue <- containerID
}

func newContainersPathsCache() *containersPathsCache {
	return &containersPathsCache{
		processedPaths: make(map[string]*lru.Cache[containerFilePath, struct{}]),
	}
}

// containersPathsCache holds already analyzed paths for each container.
type containersPathsCache struct {
	// mu only locks main map. Per container map uses lru with separate mutex.
	mu             sync.RWMutex
	processedPaths map[string]*lru.Cache[containerFilePath, struct{}]
}

func (c *containersPathsCache) containsPath(containerID string, key containerFilePath) bool {
	c.mu.RLock()
	cont, found := c.processedPaths[containerID]
	c.mu.RUnlock()

	if !found {
		return false
	}
	_, found = cont.Get(key)
	return found
}

func (c *containersPathsCache) savePath(containerID string, key containerFilePath) {
	c.mu.RLock()
	cont, found := c.processedPaths[containerID]
	c.mu.RUnlock()

	if !found {
		lcache, _ := lru.New[containerFilePath, struct{}](1000)
		cont = lcache
		cont.Add(key, struct{}{})

		c.mu.Lock()
		c.processedPaths[containerID] = cont
		c.mu.Unlock()
		return
	}
	cont.Add(key, struct{}{})
}

func (c *containersPathsCache) delete(containerID string) {
	c.mu.Lock()
	delete(c.processedPaths, containerID)
	c.mu.Unlock()
}

type containerFilePath struct {
	containerID string
	filePath    string
}
