package pipeline

import (
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/elastic/go-freelru"
	"github.com/samber/lo"
	"github.com/shirou/gopsutil/v4/disk"

	kubepb "github.com/castai/kvisor/api/v1/kube"
	"github.com/castai/kvisor/pkg/logging"
)

const sectorSizeBytes = 512
const hostPathRoot = "/proc/1/root"

type BlockDeviceMetric struct {
	Name            string    `avro:"name"`
	NodeName        string    `avro:"node_name"`
	NodeTemplate    *string   `avro:"node_template"`
	ReadIOPS        int64     `avro:"read_iops"`
	WriteIOPS       int64     `avro:"write_iops"`
	ReadThroughput  int64     `avro:"read_throughput"`
	WriteThroughput int64     `avro:"write_throughput"`
	Size            *int64    `avro:"size"`
	PhysicalDevices []string  `avro:"physical_devices"`
	Timestamp       time.Time `avro:"ts"`

	// Internal fields for calculation (raw cumulative counters)
	readCount  uint64
	writeCount uint64
	readBytes  uint64
	writeBytes uint64
}

type FilesystemMetric struct {
	Devices      []string  `avro:"devices"`
	NodeName     string    `avro:"node_name"`
	NodeTemplate *string   `avro:"node_template"`
	MountPoint   string    `avro:"mount_point"`
	TotalSize    *int64    `avro:"total_size"`
	UsedSpace    *int64    `avro:"used_space"`
	Timestamp    time.Time `avro:"ts"`
}

type storageMetricsState struct {
	blockDevices map[string]*BlockDeviceMetric
	filesystems  map[string]*FilesystemMetric
}

type StorageInfoProvider interface {
	BuildFilesystemMetrics(timestamp time.Time) ([]FilesystemMetric, error)
	BuildBlockDeviceMetrics(timestamp time.Time) ([]BlockDeviceMetric, error)
}

type SysfsStorageInfoProvider struct {
	log            *logging.Logger
	diskClient     DiskInterface
	storageState   *storageMetricsState
	nodeName       string
	hostRootPath   string
	sysBlockPrefix string
	kubeClient     kubepb.KubeAPIClient
	nodeCache      *freelru.SyncedLRU[string, *kubepb.Node]
}

func NewStorageInfoProvider(log *logging.Logger, kubeClient kubepb.KubeAPIClient) (StorageInfoProvider, error) {
	nodeCache, err := freelru.NewSynced[string, *kubepb.Node](4, func(k string) uint32 {
		return uint32(xxhash.Sum64String(k)) // nolint:gosec
	})
	if err != nil {
		return nil, fmt.Errorf("nodeCache can not be initialized")
	}

	return &SysfsStorageInfoProvider{
		storageState: &storageMetricsState{
			blockDevices: make(map[string]*BlockDeviceMetric),
			filesystems:  make(map[string]*FilesystemMetric),
		},
		log:            log,
		diskClient:     NewDiskClient(),
		nodeName:       os.Getenv("NODE_NAME"),
		hostRootPath:   hostPathRoot,
		sysBlockPrefix: "",
		kubeClient:     kubeClient,
		nodeCache:      nodeCache,
	}, nil
}

func (s *SysfsStorageInfoProvider) getNode() (*kubepb.Node, error) {
	if s.kubeClient == nil {
		return nil, fmt.Errorf("kube client is not initialized")
	}

	if s.nodeCache != nil {
		node, found := s.nodeCache.Get(s.nodeName)
		if found {
			return node, nil
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := s.kubeClient.GetNode(ctx, &kubepb.GetNodeRequest{
		Name: s.nodeName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get node %s: %w", s.nodeName, err)
	}

	if resp.Node == nil {
		return nil, fmt.Errorf("failed to get node")
	}

	if s.nodeCache != nil {
		s.nodeCache.Add(s.nodeName, resp.Node)
	}

	return resp.Node, nil
}

func (s *SysfsStorageInfoProvider) getNodeTemplate() (*string, error) {
	node, err := s.getNode()
	if err != nil {
		return nil, err
	}

	if node.Labels == nil {
		return nil, fmt.Errorf("failed to get labels")
	}

	nodeTemplate, exists := node.Labels["scheduling.cast.ai/node-template"]
	if !exists {
		return nil, nil
	}

	return &nodeTemplate, nil
}

func (s *SysfsStorageInfoProvider) BuildFilesystemMetrics(timestamp time.Time) ([]FilesystemMetric, error) {
	partitions, err := s.diskClient.Partitions(false) // false = only physical devices
	if err != nil {
		return nil, fmt.Errorf("failed to get partitions: %w", err)
	}

	filesystemMetrics := make([]FilesystemMetric, 0, len(partitions))
	for _, partition := range partitions {
		metric := s.buildFilesystemMetric(partition, timestamp)
		filesystemMetrics = append(filesystemMetrics, metric)
	}

	return filesystemMetrics, nil
}

func (s *SysfsStorageInfoProvider) buildFilesystemMetric(partition disk.PartitionStat, timestamp time.Time) FilesystemMetric {
	fileSystemPath := s.hostRootPath + partition.Mountpoint
	diskStats, diskErr := s.diskClient.GetDiskStats(fileSystemPath)
	if diskErr != nil {
		s.log.Warnf("failed to build file system metric: %v", diskErr)
	}

	nodeTemplate, err := s.getNodeTemplate()
	if err != nil {
		s.log.Warnf("failed to get node template for %s: %v", partition.Mountpoint, err)
	}

	var totalSize, usedSpace *int64
	if diskErr == nil && diskStats != nil {
		total := safeUint64ToInt64(diskStats.Total)
		used := safeUint64ToInt64(diskStats.Used)
		totalSize, usedSpace = &total, &used
	}

	return FilesystemMetric{
		Devices:      s.getBackingDevices(partition.Device),
		NodeName:     s.nodeName,
		NodeTemplate: nodeTemplate,
		MountPoint:   partition.Mountpoint,
		TotalSize:    totalSize,
		UsedSpace:    usedSpace,
		Timestamp:    timestamp,
	}
}

// getBackingDevices resolves a device to its backing device.
// For LVM: "/dev/mapper/vg-lv" → "/dev/dm-1"
// For regular devices: "/dev/sda1" → "/dev/sda1"
func (s *SysfsStorageInfoProvider) getBackingDevices(device string) []string {
	if slaves := s.getLVMDMDevice(device); len(slaves) > 0 {
		return slaves
	}

	return []string{device}
}

// getLVMDMDevice resolves LVM logical volumes to their dm device.
// It handles the symlink chain: /dev/mapper/vg-lv → /dev/dm-X
func (s *SysfsStorageInfoProvider) getLVMDMDevice(device string) []string {
	if !strings.HasPrefix(device, "/dev/mapper/") {
		return nil
	}
	hostMapperPath := s.hostRootPath + device
	linkTarget, err := os.Readlink(hostMapperPath)
	if err != nil {
		s.log.Errorf("symlink resolution failed for %s: %v", device, err)
		return nil
	}
	return []string{"/dev/" + filepath.Base(linkTarget)}
}

func (s *SysfsStorageInfoProvider) resolvePhysicalDevices(blockName string) []string {
	visited := make(map[string]bool)
	physicalDevices := s.getPhysicalDevicesRecursive(blockName, visited)
	return s.deduplicateDevices(physicalDevices)
}

func (s *SysfsStorageInfoProvider) getPhysicalDevicesRecursive(blockName string, visited map[string]bool) []string {
	if visited[blockName] {
		s.log.Warnf("circular dependency detected for device %s", blockName)
		return []string{"/dev/" + blockName}
	}
	visited[blockName] = true

	slaves, err := s.getBlockSlaves(blockName)
	if err != nil {
		s.log.Debugf("cannot read slaves for %s: %v", blockName, err)
		return []string{"/dev/" + blockName}
	}

	if len(slaves) == 0 {
		return []string{"/dev/" + blockName}
	}

	var allPhysicalDevices []string
	for _, slave := range slaves {
		slavePhysical := s.getPhysicalDevicesRecursive(slave, visited)
		allPhysicalDevices = append(allPhysicalDevices, slavePhysical...)
	}

	return allPhysicalDevices
}

func (s *SysfsStorageInfoProvider) deduplicateDevices(devices []string) []string {
	seen := make(map[string]bool)
	unique := make([]string, 0, len(devices))

	for _, device := range devices {
		if !seen[device] {
			seen[device] = true
			unique = append(unique, device)
		}
	}

	sort.Strings(unique)
	return unique
}

func (s *SysfsStorageInfoProvider) BuildBlockDeviceMetrics(timestamp time.Time) ([]BlockDeviceMetric, error) {
	ioStats, err := s.diskClient.IOCounters()
	if err != nil {
		return nil, fmt.Errorf("failed to get IO counters: %w", err)
	}

	blockMetrics := make([]BlockDeviceMetric, 0, len(ioStats))

	for blockName, stat := range ioStats {
		current := s.buildBlockDeviceMetric(blockName, stat, timestamp)

		prev, exists := s.storageState.blockDevices[current.Name]
		if exists {
			timeDiff := current.Timestamp.Sub(prev.Timestamp).Seconds()
			if timeDiff > 0 {
				calculateBlockDeviceRates(&current, prev, timeDiff)
				blockMetrics = append(blockMetrics, current)
			}
		}

		s.storageState.blockDevices[current.Name] = &current
	}

	return blockMetrics, nil
}

func (s *SysfsStorageInfoProvider) buildBlockDeviceMetric(blockName string, stat disk.IOCountersStat, timestamp time.Time) BlockDeviceMetric {
	diskSize, err := s.getDeviceSize(blockName)
	if err != nil {
		s.log.Warnf("failed to get disk usage for %s: %v", blockName, err)
	}

	physicalDevices := s.resolvePhysicalDevices(blockName)

	nodeTemplate, err := s.getNodeTemplate()
	if err != nil {
		s.log.Warnf("failed to get node template for %s: %v", blockName, err)
	}

	return BlockDeviceMetric{
		Name:            blockName,
		NodeName:        s.nodeName,
		NodeTemplate:    nodeTemplate,
		PhysicalDevices: physicalDevices,
		Size:            diskSize,
		Timestamp:       timestamp,
		readCount:       stat.ReadCount,
		writeCount:      stat.WriteCount,
		readBytes:       stat.ReadBytes,
		writeBytes:      stat.WriteBytes,
	}
}

func (s *SysfsStorageInfoProvider) getDeviceSize(deviceName string) (*int64, error) {
	devicePath := filepath.Join(s.sysBlockPrefix, "sys", "block", deviceName, "size")
	if sectors, err := s.getDeviceSectorCount(devicePath); err == nil && sectors > 0 {
		return lo.ToPtr(sectors * sectorSizeBytes), nil
	}

	if sectors, err := s.getPartitionSectorCount(deviceName); err == nil && sectors > 0 {
		return lo.ToPtr(sectors * sectorSizeBytes), nil
	}

	return nil, fmt.Errorf("failed to get size for device %s", deviceName)
}

func (s *SysfsStorageInfoProvider) getDeviceSectorCount(devicePath string) (int64, error) {
	data, err := os.ReadFile(devicePath)
	if err != nil {
		return 0, err
	}

	sizeStr := strings.TrimSpace(string(data))
	sectors, err := strconv.ParseInt(sizeStr, 10, 64)
	if err != nil {
		return 0, err
	}

	return sectors, nil
}

func (s *SysfsStorageInfoProvider) getPartitionSectorCount(deviceName string) (int64, error) {
	blockDir := filepath.Join(s.sysBlockPrefix, "sys", "block")
	entries, err := os.ReadDir(blockDir)
	if err != nil {
		return 0, err
	}

	for _, entry := range entries {
		entryPath := filepath.Join(blockDir, entry.Name())
		stat, err := os.Stat(entryPath)
		if err != nil || !stat.IsDir() {
			continue
		}

		partitionPath := filepath.Join(blockDir, entry.Name(), deviceName, "size")
		if sectors, err := s.getDeviceSectorCount(partitionPath); err == nil && sectors > 0 {
			return sectors, nil
		}
	}

	return 0, fmt.Errorf("partition %s not found", deviceName)
}

func (s *SysfsStorageInfoProvider) getBlockSlaves(blockName string) ([]string, error) {
	slavesPath := filepath.Join(s.sysBlockPrefix, "sys", "block", blockName, "slaves")
	entries, err := os.ReadDir(slavesPath)
	if err != nil {
		return nil, err
	}

	var slaves []string
	for _, entry := range entries {
		if !entry.IsDir() {
			slaves = append(slaves, entry.Name())
		}
	}

	return slaves, nil
}

// safeUint64ToInt64 safely converts uint64 to int64, clamping to MaxInt64 if overflow would occur
func safeUint64ToInt64(val uint64) int64 {
	if val > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(val)
}

func safeDelta(current, previous uint64) int64 {
	if current >= previous {
		return safeUint64ToInt64(current - previous)
	}
	return 0
}

func calculateBlockDeviceRates(current *BlockDeviceMetric, prev *BlockDeviceMetric, timeDiff float64) {
	timeDiffSecs := int64(timeDiff)

	readOpsDelta := safeDelta(current.readCount, prev.readCount)
	writeOpsDelta := safeDelta(current.writeCount, prev.writeCount)
	readBytesDelta := safeDelta(current.readBytes, prev.readBytes)
	writeBytesDelta := safeDelta(current.writeBytes, prev.writeBytes)

	current.ReadIOPS = readOpsDelta / timeDiffSecs
	current.WriteIOPS = writeOpsDelta / timeDiffSecs
	current.ReadThroughput = readBytesDelta / timeDiffSecs
	current.WriteThroughput = writeBytesDelta / timeDiffSecs
}
