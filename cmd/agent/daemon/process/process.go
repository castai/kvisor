package process

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/castai/kvisor/pkg/logging"
)

var (
	ErrContainerNotFound  = errors.New("container not found")
	searchKubeletKubepods = []byte("/kubepods")
	searchDockerPids      = []byte("pids:/docker")
	sep                   = []byte("/")
)

type containersCacheValue struct {
	containerID string
	ts          *atomic.Int64
}

func NewClient(log *logging.Logger, procDir string) *Client {
	return &Client{
		log:             log,
		procDir:         procDir,
		refreshDuration: 2 * time.Minute,
		cache:           map[int]containersCacheValue{},
	}
}

type Client struct {
	log     *logging.Logger
	procDir string

	refreshDuration time.Duration
	cache           map[int]containersCacheValue
	mu              sync.RWMutex
}

func (c *Client) Start(ctx context.Context) {
	c.runRefreshLoop(ctx)
}

func (c *Client) GetContainerID(pid int) (string, error) {
	if pid == 0 {
		return "", ErrContainerNotFound
	}
	// Fast path. Check cached
	cacheKey := pid
	c.mu.RLock()
	cachedVal, found := c.cache[cacheKey]
	c.mu.RUnlock()
	if found {
		cachedVal.ts.Store(time.Now().UTC().Unix())
		return cachedVal.containerID, nil
	}

	// Slow path. Read from file system.
	cid, err := c.getContainerIDFromFile(pid)
	if err != nil {
		return "", err
	}

	// Cache value.
	c.addContainerToCache(pid, cid)

	return cid, nil
}

func (c *Client) RemoveContainer(pid int) {
	c.mu.Lock()
	delete(c.cache, pid)
	c.mu.Unlock()
}

func (c *Client) getContainerIDFromFile(pid int) (string, error) {
	cgroupPath := path.Join(c.procDir, strconv.Itoa(pid), "cgroup")
	f, err := os.Open(cgroupPath)
	if err != nil {
		return "", fmt.Errorf("opening file %s: %w", cgroupPath, ErrContainerNotFound)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()
		if bytes.Contains(line, searchKubeletKubepods) || bytes.Contains(line, searchDockerPids) {
			lastSegment := bytes.LastIndex(line, sep)
			containerID := string(line[lastSegment+1:])
			if strings.Contains(containerID, "cri-containerd") {
				containerID = strings.Replace(containerID, "cri-containerd-", "", 1)
				containerID = strings.Replace(containerID, ".scope", "", 1)
			}
			return containerID, nil
		}
	}
	return "", ErrContainerNotFound
}

func (c *Client) runRefreshLoop(ctx context.Context) {
	ticker := time.NewTicker(c.refreshDuration)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.refresh()
		}
	}
}

func (c *Client) refresh() {
	var pidsToRefresh []int
	var deletedPidsCount int
	deletedOlderThan := time.Now().UTC().Add(-1 * time.Minute)
	c.mu.Lock()
	for pid, val := range c.cache {
		if time.Unix(val.ts.Load(), 0).Before(deletedOlderThan) {
			delete(c.cache, pid)
			deletedPidsCount++
		} else {
			pidsToRefresh = append(pidsToRefresh, pid)
		}
	}
	c.mu.Unlock()

	var changedPidsCount int
	for _, pid := range pidsToRefresh {
		cid, err := c.getContainerIDFromFile(pid)
		if err != nil && !errors.Is(err, ErrContainerNotFound) {
			c.log.Errorf("refresh: getting container id by pid: %v", err)
			continue
		}
		if cid != "" {
			c.mu.RLock()
			cachedVal, found := c.cache[pid]
			c.mu.RUnlock()

			if found && cachedVal.containerID != cid {
				c.addContainerToCache(pid, cid)
				changedPidsCount++
			}
		}
	}

	c.log.Debugf("process containers refresh done, deleted=%d, changed=%d", deletedPidsCount, changedPidsCount)
}

func (c *Client) addContainerToCache(pid int, cid string) {
	c.mu.Lock()
	ts := &atomic.Int64{}
	ts.Store(time.Now().UTC().Unix())
	c.cache[pid] = containersCacheValue{
		containerID: cid,
		ts:          ts,
	}
	c.mu.Unlock()
}
