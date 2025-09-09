package pipeline

import (
	"fmt"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/shirou/gopsutil/v4/disk"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const sectorSizeBytes = 512

type BlockDeviceMetrics struct {
	Name            string    `avro:"name"`
	PhysicalDevices []string  `avro:"physical_devices"`
	NodeName        string    `avro:"node_name"`
	ReadIOPS        int64     `avro:"read_iops"`
	WriteIOPS       int64     `avro:"write_iops"`
	ReadThroughput  float64   `avro:"read_throughput"`
	WriteThroughput float64   `avro:"write_throughput"`
	Size            int64     `avro:"size"`
	Timestamp       time.Time `avro:"ts"`
}

type FilesystemMetrics struct {
	Devices    []string  `avro:"devices"`
	NodeName   string    `avro:"node_name"`
	MountPoint string    `avro:"mount_point"`
	TotalSize  int64     `avro:"total_size"`
	UsedSpace  int64     `avro:"used_space"`
	Timestamp  time.Time `avro:"ts"`
}

type storageMetricsState struct {
	blockDevices map[string]*BlockDeviceMetrics
	filesystems  map[string]*FilesystemMetrics
}

type StorageInfoProvider interface {
	BuildFilesystemMetrics(timestamp time.Time) ([]FilesystemMetrics, error)
	BuildBlockDeviceMetrics(timestamp time.Time) ([]BlockDeviceMetrics, error)
}

type SysfsStorageInfoProvider struct {
	log            *logging.Logger
	diskClient     DiskInterface
	storageState   *storageMetricsState
	nodeName       string
	hostRootPath   string
	sysBlockPrefix string
}

func NewStorageInfoProvider(log *logging.Logger, nodeName string) StorageInfoProvider {
	return &SysfsStorageInfoProvider{
		storageState: &storageMetricsState{
			blockDevices: make(map[string]*BlockDeviceMetrics),
			filesystems:  make(map[string]*FilesystemMetrics),
		},
		log:            log,
		diskClient:     NewDiskClient(),
		nodeName:       nodeName,
		hostRootPath:   "/proc/1/root",
		sysBlockPrefix: "",
	}
}

func (s *SysfsStorageInfoProvider) BuildFilesystemMetrics(timestamp time.Time) ([]FilesystemMetrics, error) {
	partitions, err := s.diskClient.Partitions(false) // false = only physical devices
	if err != nil {
		return nil, fmt.Errorf("failed to get partitions: %w", err)
	}

	filesystemMetrics := make([]FilesystemMetrics, 0, len(partitions))
	for _, partition := range partitions {
		metric, err := s.buildFilesystemMetric(partition, timestamp)
		if err != nil {
			s.log.Warnf("failed to build file system metric: %v", err)
			continue
		}
		filesystemMetrics = append(filesystemMetrics, *metric)
	}

	s.log.Debugf("collected %d filesystem metrics", len(filesystemMetrics))
	return filesystemMetrics, nil
}

func (s *SysfsStorageInfoProvider) buildFilesystemMetric(partition disk.PartitionStat, timestamp time.Time) (*FilesystemMetrics, error) {
	fileSystemPath := s.hostRootPath + partition.Mountpoint
	usage, err := s.diskClient.Usage(fileSystemPath)
	if err != nil {
		return nil, err
	}

	return &FilesystemMetrics{
		Devices:    s.getBackingDevices(partition.Device),
		NodeName:   s.nodeName,
		MountPoint: partition.Mountpoint,
		TotalSize:  safeUint64ToInt64(usage.Total),
		UsedSpace:  safeUint64ToInt64(usage.Used),
		Timestamp:  timestamp,
	}, nil
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

// getLVMSlaves resolves LVM logical volumes to their dm device.
// It handles the symlink chain: /dev/mapper/vg-lv → /dev/dm-X
func (s *SysfsStorageInfoProvider) getLVMDMDevice(device string) []string {
	if !strings.HasPrefix(device, "/dev/mapper/") {
		return nil
	}
	hostMapperPath := s.hostRootPath + device
	linkTarget, err := os.Readlink(hostMapperPath)
	if err != nil {
		s.log.Debugf("symlink resolution failed for %s: %v", device, err)
		return nil
	}
	return []string{"/dev/" + filepath.Base(linkTarget)}
}

func (s *SysfsStorageInfoProvider) resolvePhysicalDevices(blockName string) []string {
	visited := make(map[string]bool)
	physicalDevices := s.getPhysicalDevicesRecursive(blockName, visited)

	if len(physicalDevices) == 0 {
		return []string{"/dev/" + blockName}
	}

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

func (s *SysfsStorageInfoProvider) BuildBlockDeviceMetrics(timestamp time.Time) ([]BlockDeviceMetrics, error) {
	ioStats, err := s.diskClient.IOCounters()
	if err != nil {
		return nil, fmt.Errorf("failed to get IO counters: %w", err)
	}

	blockMetrics := make([]BlockDeviceMetrics, 0, len(ioStats))

	for blockName, stat := range ioStats {
		current := s.buildBlockDeviceMetric(blockName, stat, s.nodeName, timestamp)
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

func (s *SysfsStorageInfoProvider) buildBlockDeviceMetric(blockName string, stat disk.IOCountersStat, nodeName string, timestamp time.Time) BlockDeviceMetrics {
	diskUsage, err := s.getDeviceSize(blockName)
	if err != nil {
		s.log.Warnf("failed to get disk usage for %s: %v", blockName, err)
		diskUsage = 0
	}

	physicalDevices := s.resolvePhysicalDevices(blockName)

	return BlockDeviceMetrics{
		Name:            blockName,
		PhysicalDevices: physicalDevices,
		NodeName:        nodeName,
		ReadIOPS:        safeUint64ToInt64(stat.ReadCount),
		WriteIOPS:       safeUint64ToInt64(stat.WriteCount),
		ReadThroughput:  float64(stat.ReadBytes),
		WriteThroughput: float64(stat.WriteBytes),
		Size:            diskUsage,
		Timestamp:       timestamp,
	}
}

func (p *SysfsStorageInfoProvider) getDeviceSize(deviceName string) (int64, error) {
	devicePath := fmt.Sprintf("%s/sys/block/%s/size", p.sysBlockPrefix, deviceName)
	if sectors, err := p.getDeviceSectorCount(devicePath); err == nil && sectors > 0 {
		return sectors * sectorSizeBytes, nil
	}

	if sectors, err := p.getPartitionSectorCount(deviceName); err == nil && sectors > 0 {
		return sectors * sectorSizeBytes, nil
	}

	return 0, fmt.Errorf("failed to get size for device %s", deviceName)
}

func (p *SysfsStorageInfoProvider) getDeviceSectorCount(devicePath string) (int64, error) {
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

func (p *SysfsStorageInfoProvider) getPartitionSectorCount(deviceName string) (int64, error) {
	blockDir := p.sysBlockPrefix + "/sys/block"
	entries, err := os.ReadDir(blockDir)
	if err != nil {
		return 0, err
	}

	for _, entry := range entries {
		entryPath := fmt.Sprintf("%s/%s", blockDir, entry.Name())
		stat, err := os.Stat(entryPath)
		if err != nil || !stat.IsDir() {
			continue
		}

		partitionPath := fmt.Sprintf("%s/%s/%s/size", blockDir, entry.Name(), deviceName)
		if sectors, err := p.getDeviceSectorCount(partitionPath); err == nil && sectors > 0 {
			return sectors, nil
		}
	}

	return 0, fmt.Errorf("partition %s not found", deviceName)
}

func (p *SysfsStorageInfoProvider) getBlockSlaves(blockName string) ([]string, error) {
	slavesPath := fmt.Sprintf("%s/sys/block/%s/slaves", p.sysBlockPrefix, blockName)
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
