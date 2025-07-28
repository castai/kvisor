package cgroup

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/castai/kvisor/cmd/agent/daemon/metrics"
	"github.com/castai/kvisor/pkg/logging"
)

var (
	ErrCgroupNotFound = errors.New("cgroup not found")
)

type ID = uint64

const (
	procCgroups             = "/proc/cgroups"
	cgroupControllersFile   = "/sys/fs/cgroup/cgroup.controllers"
	cgroupDefaultController = "cpuset"
)

type Version uint8

func (v Version) String() string {
	if v == V1 {
		return "V1"
	}
	if v == V2 {
		return "V2"
	}
	return ""
}

const (
	V1 = iota
	V2
)

// Represents the internal ID of a container runtime
type ContainerRuntimeID int

const (
	UnknownRuntime ContainerRuntimeID = iota
	DockerRuntime
	ContainerdRuntime
	CrioRuntime
	PodmanRuntime
	GardenRuntime
)

var runtimeStringMap = map[ContainerRuntimeID]string{
	UnknownRuntime:    "unknown",
	DockerRuntime:     "docker",
	ContainerdRuntime: "containerd",
	CrioRuntime:       "crio",
	PodmanRuntime:     "podman",
	GardenRuntime:     "garden", // there is no enricher (yet ?) for garden
}

func (runtime ContainerRuntimeID) String() string {
	return runtimeStringMap[runtime]
}

func FromString(str string) ContainerRuntimeID {
	switch str {
	case "docker":
		return DockerRuntime
	case "crio":
		return CrioRuntime
	case "cri-o":
		return CrioRuntime
	case "podman":
		return PodmanRuntime
	case "containerd":
		return ContainerdRuntime
	case "garden":
		return GardenRuntime

	default:
		return UnknownRuntime
	}
}

type Client struct {
	version            Version
	cgRoot             string
	cgroupCacheByID    map[ID]func() *Cgroup
	cgroupMu           sync.RWMutex
	defaultHierarchyID uint32
	psiEnabled         bool
}

func NewClient(log *logging.Logger, root string, psiEnabled bool) (*Client, error) {
	version, defaultHierarchyID, err := getDefaultVersionAndHierarchy(log)
	if err != nil {
		return nil, fmt.Errorf("getting default cgroups version: %w", err)
	}
	log.WithField("component", "cgroup").Infof("cgroups detected version=%s, root=%s", version, root)
	return &Client{
		version:            version,
		cgRoot:             root,
		cgroupCacheByID:    make(map[uint64]func() *Cgroup),
		defaultHierarchyID: defaultHierarchyID,
		psiEnabled:         psiEnabled,
	}, nil
}

func (c *Client) GetCgroupsRootPath() string {
	return c.cgRoot
}

func (c *Client) lookupCgroupForIDInCache(id ID) (*Cgroup, bool) {
	c.cgroupMu.RLock()
	defer c.cgroupMu.RUnlock()

	if cgroup, found := c.cgroupCacheByID[id]; found {
		return cgroup(), true
	}
	return nil, false
}

func (c *Client) LoadCgroupByID(cgroupID ID) (*Cgroup, error) {
	if cg, found := c.lookupCgroupForIDInCache(cgroupID); found {
		return cg, nil
	}

	metrics.AgentFindCgroupFS.Inc()

	cgroupPath, _ := c.findCgroupPathForID(cgroupID)

	if cgroupPath == "" {
		return nil, ErrCgroupNotFound
	}

	cgroup := c.loadCgroupForIDAndPath(cgroupID, cgroupPath)

	c.cacheCgroup(cgroup)

	return cgroup, nil
}

func (c *Client) LoadCgroupByContainerID(containerID string) (*Cgroup, error) {
	cgroupPath, cgroupID := c.findCgroupPathForContainerID(containerID)
	if cgroupPath == "" {
		return nil, ErrCgroupNotFound
	}
	cgroup := c.loadCgroupForIDAndPath(cgroupID, cgroupPath)
	if cgroup.ContainerID == "" {
		return nil, ErrCgroupNotFound
	}
	cgroup.ContainerID = containerID
	c.cacheCgroup(cgroup)

	return cgroup, nil
}

func (c *Client) LoadCgroup(id ID, path string) {
	c.cgroupMu.Lock()
	defer c.cgroupMu.Unlock()

	path = c.fixCgroupPath(path)

	c.cgroupCacheByID[id] = sync.OnceValue(func() *Cgroup {
		cgroup := c.loadCgroupForIDAndPath(id, path)
		return cgroup
	})
}

var systemSliceRegexp = regexp.MustCompile(`^/system\.slice/docker-[a-f0-9]+\.scope/`)

func (c *Client) fixCgroupPath(path string) string {
	// Kind clusters runs inside a container. eBPF mkdir events returns full path of the kernel view,
	// but we mount /sys/fs/cgroups from the kind node (aka docker in docker).
	// This is a simple fix for local kind clusters.
	if strings.HasPrefix(path, "/system.slice/docker-") {
		path = systemSliceRegexp.ReplaceAllString(path, "/")
	}
	rootDir := c.cgRoot
	if c.version == V1 {
		// Cgroup V1 may not always return path containing a device.
		if !strings.HasPrefix(path, "/cpuset") {
			rootDir = c.getCgroupSearchBasePath()
		}
	}

	if !strings.HasPrefix(path, rootDir) {
		path = filepath.Join(rootDir, path)
	}
	return path
}

func (c *Client) loadCgroupForIDAndPath(cgroupID ID, cgroupPath string) *Cgroup {
	containerID, containerRuntime := GetContainerIdFromCgroup(cgroupPath)

	return &Cgroup{
		Id:               cgroupID,
		ContainerID:      containerID,
		ContainerRuntime: containerRuntime,
		Path:             cgroupPath,
		statsGetterFunc:  newCgroupStatsGetterFunc(c.version, c.psiEnabled, c.cgRoot, cgroupPath),
	}
}

func (c *Client) getCgroupSearchBasePath() string {
	rootDir := c.cgRoot

	if c.version == V1 {
		// TODO: we hardcode this for now, but in the future we might want to make this configurable
		// (cpuset might not always be the first cgroup reported by the kernel)
		rootDir = filepath.Join(rootDir, "cpuset")
	}

	return rootDir
}

func (c *Client) findCgroupPathForID(cgroupId ID) (string, ID) {
	found := errors.New("found")
	retPath := ""
	var cgroupID ID

	rootDir := c.getCgroupSearchBasePath()

	_ = filepath.WalkDir(rootDir, func(path string, info fs.DirEntry, err error) error {
		// nolint:nilerr
		if err != nil || !info.IsDir() {
			return nil
		}

		fileInfo, err := info.Info()
		if err != nil {
			return err
		}

		stat, ok := fileInfo.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("unexpected stat")
		}

		if (stat.Ino & 0xFFFFFFFF) == (cgroupId & 0xFFFFFFFF) {
			retPath = path
			cgroupID = stat.Ino
			return found
		}

		return nil
	})

	if retPath == rootDir {
		return "", 0
	}

	return retPath, cgroupID
}

func (c *Client) findCgroupPathForContainerID(containerID string) (string, ID) {
	found := errors.New("found")
	retPath := ""
	rootDir := c.getCgroupSearchBasePath()
	var cgroupID ID
	_ = filepath.WalkDir(rootDir, func(path string, info fs.DirEntry, err error) error {
		// nolint:nilerr
		if err != nil || !info.IsDir() {
			return nil
		}
		base := filepath.Base(path)
		if strings.Contains(base, containerID) {
			fileInfo, err := info.Info()
			if err != nil {
				return err
			}
			stat, ok := fileInfo.Sys().(*syscall.Stat_t)
			if !ok {
				return errors.New("unexpected stat")
			}
			retPath = path
			cgroupID = stat.Ino
			return found
		}
		return nil
	})
	return retPath, cgroupID
}

func (c *Client) DefaultCgroupVersion() Version {
	return c.version
}

func (c *Client) IsDefaultHierarchy(hierarchyID uint32) bool {
	// There is no such thing as a default hierarchy in cgroup v2, as this only applies to cgroup v1,
	// where we need to ensure to always use the same type of cgroup for handling events.
	if c.DefaultCgroupVersion() == V2 {
		return true
	}

	return c.defaultHierarchyID == hierarchyID
}

func getDefaultVersionAndHierarchy(log *logging.Logger) (Version, uint32, error) {
	// 1st Method: already mounted cgroupv1 filesystem

	if ok, _ := isCgroupV2MountedAndDefault(); ok {
		return V2, 0, nil
	}

	//
	// 2nd Method: From cgroup man page:
	// ...
	// 2. The unique ID of the cgroup hierarchy on which this
	//    controller is mounted. If multiple cgroups v1
	//    controllers are bound to the same hierarchy, then each
	//    will show the same hierarchy ID in this field.  The
	//    value in this field will be 0 if:
	//
	//    a) the controller is not mounted on a cgroups v1
	//       hierarchy;
	//    b) the controller is bound to the cgroups v2 single
	//       unified hierarchy; or
	//    c) the controller is disabled (see below).
	// ...

	var value uint64
	file, err := os.Open(procCgroups)
	if err != nil {
		return 0, 0, fmt.Errorf("opening %s: %w", procCgroups, err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Warnf("closing %s: %v", procCgroups, err)
		}
	}()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.Fields(scanner.Text())
		if line[0] != cgroupDefaultController {
			continue
		}
		value, err = strconv.ParseUint(line[1], 10, 32)
		if err != nil {
			return 0, 0, fmt.Errorf("parsing %s: %w", procCgroups, err)
		}
	}

	if value == 0 { // == (a), (b) or (c)
		return V2, 0, nil
	}

	return V1, uint32(value), nil // nolint:gosec
}

func isCgroupV2MountedAndDefault() (bool, error) {
	_, err := os.Stat(cgroupControllersFile)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("opening %s: %w", cgroupControllersFile, err)
	}

	return true, nil
}

var (
	containerIdFromCgroupRegex       = regexp.MustCompile(`^[A-Fa-f0-9]{64}$`)
	gardenContainerIdFromCgroupRegex = regexp.MustCompile(`^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){4}$`)
)

// GetContainerIdFromCgroup extracts container id and its runtime from path. It returns
// the container id and the used runtime.
func GetContainerIdFromCgroup(cgroupPath string) (string, ContainerRuntimeID) {
	cgroupParts := strings.Split(cgroupPath, "/")

	// search from the end to get the most inner container id
	for i := len(cgroupParts) - 1; i >= 0; i = i - 1 {
		pc := cgroupParts[i]
		if len(pc) < 28 {
			continue // container id is at least 28 characters long
		}

		runtime := UnknownRuntime
		id := strings.TrimSuffix(pc, ".scope")

		switch {
		case strings.HasPrefix(id, "docker-"):
			runtime = DockerRuntime
			id = strings.TrimPrefix(id, "docker-")
		case strings.HasPrefix(id, "crio-"):
			runtime = CrioRuntime
			id = strings.TrimPrefix(id, "crio-")
		case strings.HasPrefix(id, "cri-containerd-"):
			runtime = ContainerdRuntime
			id = strings.TrimPrefix(id, "cri-containerd-")
		case strings.Contains(pc, ":cri-containerd:"):
			runtime = ContainerdRuntime
			id = pc[strings.LastIndex(pc, ":cri-containerd:")+len(":cri-containerd:"):]
		case strings.HasPrefix(id, "libpod-"):
			runtime = PodmanRuntime
			id = strings.TrimPrefix(id, "libpod-")
		}

		if matched := containerIdFromCgroupRegex.MatchString(id); matched {
			if runtime == UnknownRuntime && i > 0 && cgroupParts[i-1] == "docker" {
				// non-systemd docker with format: .../docker/01adbf...f26db7f/
				runtime = DockerRuntime
			}
			if runtime == UnknownRuntime && i > 0 && cgroupParts[i-1] == "actions_job" {
				// non-systemd docker with format in GitHub Actions: .../actions_job/01adbf...f26db7f/
				runtime = DockerRuntime
			}
			if runtime == UnknownRuntime && i > 0 {
				for l := i; l > 0; l-- {
					if cgroupParts[l] == "kubepods" {
						runtime = DockerRuntime
						break
					}
				}
			}

			// Return the first match, closest to the root dir path component, so that the
			// container id of the outer container is returned. The container root is
			// determined by being matched on the last path part.
			return id, runtime
		}

		if matched := gardenContainerIdFromCgroupRegex.MatchString(id); matched {
			runtime = GardenRuntime
			return id, runtime
		}
	}

	// cgroup dirs unrelated to containers provides empty (containerId, runtime)
	return "", UnknownRuntime
}

func (c *Client) cacheCgroup(cgroup *Cgroup) {
	c.cgroupMu.Lock()
	c.cgroupCacheByID[cgroup.Id] = func() *Cgroup { return cgroup }
	c.cgroupMu.Unlock()
}

func (c *Client) CleanupCgroup(id ID) {
	c.cgroupMu.Lock()
	defer c.cgroupMu.Unlock()

	_, found := c.cgroupCacheByID[id]
	if !found {
		return
	}

	delete(c.cgroupCacheByID, id)
}
