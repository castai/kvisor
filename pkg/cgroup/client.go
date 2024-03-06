package cgroup

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/castai/kvisor/pkg/logging"
)

var (
	baseCgroupPath = ""

	dockerIdRegexp      = regexp.MustCompile(`([a-z0-9]{64})`)
	crioIdRegexp        = regexp.MustCompile(`crio-([a-z0-9]{64})`)
	containerdIdRegexp  = regexp.MustCompile(`cri-containerd[-:]([a-z0-9]{64})`)
	lxcIdRegexp         = regexp.MustCompile(`/lxc/([^/]+)`)
	systemSliceIdRegexp = regexp.MustCompile(`(/(system|runtime)\.slice/([^/]+))`)

	ErrCgroupNotFound = errors.New("cgroup not found")
)

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

type ContainerType uint8

const (
	ContainerTypeUnknown ContainerType = iota
	ContainerTypeStandaloneProcess
	ContainerTypeDocker
	ContainerTypeCrio
	ContainerTypeContainerd
	ContainerTypeLxc
	ContainerTypeSystemdService
	ContainerTypeSandbox
)

func (t ContainerType) String() string {
	switch t {
	case ContainerTypeStandaloneProcess:
		return "standalone"
	case ContainerTypeDocker:
		return "docker"
	case ContainerTypeCrio:
		return "crio"
	case ContainerTypeContainerd:
		return "cri-containerd"
	case ContainerTypeLxc:
		return "lxc"
	case ContainerTypeSystemdService:
		return "systemd"
	case ContainerTypeUnknown:
		return "unknown"
	case ContainerTypeSandbox:
		return "sandbox"
	default:
		return "unknown"
	}
}

type Client struct {
	version Version
	cgRoot  string
}

func NewClient(log *logging.Logger, root string) (*Client, error) {
	version, err := getDefaultVersion(log)
	if err != nil {
		return nil, fmt.Errorf("getting default cgroups version: %w", err)
	}
	log.WithField("component", "cgroup").Infof("cgroups detected version=%s, root=%s", version, root)
	return &Client{
		version: version,
		cgRoot:  root,
	}, nil
}

func (c *Client) GetCgroupForID(cgroupID uint64) (*Cgroup, error) {
	cgroupPath := c.findCgroupPathForID(cgroupID)

	if cgroupPath == "" {
		return nil, ErrCgroupNotFound
	}

	cgroup, err := c.getCgroupForPath(cgroupPath)
	if err != nil {
		return nil, err
	}

	return cgroup, nil
}

func (c *Client) GetCgroupForContainer(containerID string) (*Cgroup, error) {
	cgroupPath := c.findCgroupPathForContainerID(containerID)

	if cgroupPath == "" {
		return nil, ErrCgroupNotFound
	}

	cgroup, err := c.getCgroupForPath(cgroupPath)
	if err != nil {
		return nil, err
	}

	cgroup.ContainerID = containerID

	return cgroup, nil
}

func (c *Client) getCgroupForPath(cgroupPath string) (*Cgroup, error) {
	containerType, containerID, err := containerByCgroup(cgroupPath)
	if err != nil {
		return nil, err
	}

	cgroupID, err := getCgroupIDForPath(cgroupPath)
	if err != nil {
		return nil, err
	}

	cg := &Cgroup{
		Id:            cgroupID,
		ContainerID:   containerID,
		ContainerType: containerType,
		Path:          cgroupPath,
		cgRoot:        c.cgRoot,
		subsystems:    map[string]string{},
	}

	switch c.version {
	case V1:
		after, _ := strings.CutPrefix(cgroupPath, cg.cgRoot)
		subpath := strings.SplitN(after, "/", 1)
		if len(subpath) != 2 {
			return cg, nil
		}
		last := subpath[1]
		cg.Version = V1
		cg.subsystems = map[string]string{
			"cpu":     last,
			"cpuacct": last,
			"memory":  last,
			"blkio":   last,
		}
	case V2:
		after, _ := strings.CutPrefix(cgroupPath, cg.cgRoot)
		cg.Version = V2
		cg.subsystems = map[string]string{
			"": after,
		}
	}
	return cg, nil
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

func (c *Client) findCgroupPathForContainerID(containerID string) string {
	found := errors.New("found")
	retPath := ""

	rootDir := c.getCgroupSearchBasePath()

	_ = filepath.Walk(rootDir, func(path string, info fs.FileInfo, err error) error {
		// nolint:nilerr
		if err != nil || !info.IsDir() {
			return nil
		}

		base := filepath.Base(path)

		if strings.Contains(base, containerID) {
			retPath = path
			return found
		}

		return nil
	})

	return retPath
}

func (c *Client) findCgroupPathForID(cgroupId uint64) string {
	found := errors.New("found")
	retPath := ""

	rootDir := c.getCgroupSearchBasePath()

	_ = filepath.Walk(rootDir, func(path string, info fs.FileInfo, err error) error {
		// nolint:nilerr
		if err != nil || !info.IsDir() {
			return nil
		}

		stat, ok := info.Sys().(*syscall.Stat_t)

		if !ok {
			return errors.New("unexpected stat")
		}

		if (stat.Ino & 0xFFFFFFFF) == (cgroupId & 0xFFFFFFFF) {
			retPath = path
			return found
		}

		return nil
	})

	if retPath == rootDir {
		return ""
	}

	return retPath
}

func (c *Client) DefaultCgroupVersion() Version {
	return c.version
}

func getDefaultVersion(log *logging.Logger) (Version, error) {
	// 1st Method: already mounted cgroupv1 filesystem

	if ok, _ := isCgroupV2MountedAndDefault(); ok {
		return V2, nil
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

	var value int
	file, err := os.Open(procCgroups)
	if err != nil {
		return 0, fmt.Errorf("opening %s: %w", procCgroups, err)
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
		value, err = strconv.Atoi(line[1])
		if err != nil || value < 0 {
			return 0, fmt.Errorf("parsing %s: %w", procCgroups, err)
		}
	}

	if value == 0 { // == (a), (b) or (c)
		return V2, nil
	}

	return V1, nil
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

func NewFromProcessCgroupFile(filePath string) (*Cgroup, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	cg := &Cgroup{
		subsystems: map[string]string{},
		cgRoot:     baseCgroupPath,
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}
		for _, cgType := range strings.Split(parts[1], ",") {
			cg.subsystems[cgType] = path.Join(baseCgroupPath, parts[2])
		}
	}

	if p := cg.subsystems["cpu"]; p != "" {
		cg.Path = p
		cg.Version = V1
	} else {
		cg.Path = cg.subsystems[""]
		cg.Version = V2
	}

	if cg.ContainerType, cg.ContainerID, err = containerByCgroup(cg.Path); err != nil {
		return nil, err
	}

	if cg.Id, err = getCgroupIDForPath(cg.Path); err != nil {
		return nil, err
	}

	return cg, nil
}

func containerByCgroup(path string) (ContainerType, string, error) {
	parts := strings.Split(strings.TrimLeft(path, "/"), "/")
	if len(parts) < 2 {
		return ContainerTypeStandaloneProcess, "", nil
	}
	prefix := parts[0]
	if prefix == "user.slice" || prefix == "init.scope" {
		return ContainerTypeStandaloneProcess, "", nil
	}
	if prefix == "docker" || (prefix == "system.slice" && strings.HasPrefix(parts[1], "docker-")) {
		matches := dockerIdRegexp.FindStringSubmatch(path)
		if matches == nil {
			return ContainerTypeUnknown, "", fmt.Errorf("invalid docker cgroup %s", path)
		}
		return ContainerTypeDocker, matches[1], nil
	}
	if strings.Contains(path, "kubepods") {
		crioMatches := crioIdRegexp.FindStringSubmatch(path)
		if crioMatches != nil {
			return ContainerTypeCrio, crioMatches[1], nil
		}
		containerdMatches := containerdIdRegexp.FindStringSubmatch(path)
		if containerdMatches != nil {
			return ContainerTypeContainerd, containerdMatches[1], nil
		}
		matches := dockerIdRegexp.FindStringSubmatch(path)
		if matches == nil {
			return ContainerTypeSandbox, "", nil
		}
		return ContainerTypeDocker, matches[1], nil
	}
	if prefix == "lxc" {
		matches := lxcIdRegexp.FindStringSubmatch(path)
		if matches == nil {
			return ContainerTypeUnknown, "", fmt.Errorf("invalid lxc cgroup %s", path)
		}
		return ContainerTypeLxc, matches[1], nil
	}
	if prefix == "system.slice" || prefix == "runtime.slice" {
		matches := systemSliceIdRegexp.FindStringSubmatch(path)
		if matches == nil {
			return ContainerTypeUnknown, "", fmt.Errorf("invalid systemd cgroup %s", path)
		}
		return ContainerTypeSystemdService, matches[1], nil
	}
	return ContainerTypeUnknown, "", fmt.Errorf("unknown container: %s", path)
}

func getCgroupIDForPath(path string) (uint64, error) {
	// Lower 32 bits of the cgroup id == inode number of matching cgroupfs entry
	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil {
		return 0, err
	}
	return stat.Ino & 0xFFFFFFFF, nil
}
