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

	"github.com/shirou/gopsutil/v4/disk"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/castai/kvisor/pkg/logging"
)

const sectorSizeBytes = 512

type BlockDeviceMetrics struct {
	Name            string    `avro:"name"`
	NodeName        string    `avro:"node_name"`
	NodeTemplate    string    `avro:"node_template"`
	ReadIOPS        int64     `avro:"read_iops"`
	WriteIOPS       int64     `avro:"write_iops"`
	ReadThroughput  float64   `avro:"read_throughput"`
	WriteThroughput float64   `avro:"write_throughput"`
	Size            int64     `avro:"size"`
	PhysicalDevices []string  `avro:"physical_devices"`
	Timestamp       time.Time `avro:"ts"`
}

type FilesystemMetrics struct {
	Devices      []string  `avro:"devices"`
	NodeName     string    `avro:"node_name"`
	NodeTemplate string    `avro:"node_template"`
	MountPoint   string    `avro:"mount_point"`
	TotalSize    int64     `avro:"total_size"`
	UsedSpace    int64     `avro:"used_space"`
	Timestamp    time.Time `avro:"ts"`
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
	k8sClient      kubernetes.Interface
}

func NewStorageInfoProvider(log *logging.Logger, k8sClient kubernetes.Interface) StorageInfoProvider {
	return &SysfsStorageInfoProvider{
		storageState: &storageMetricsState{
			blockDevices: make(map[string]*BlockDeviceMetrics),
			filesystems:  make(map[string]*FilesystemMetrics),
		},
		log:            log,
		diskClient:     NewDiskClient(),
		nodeName:       os.Getenv("NODE_NAME"),
		hostRootPath:   "/proc/1/root",
		sysBlockPrefix: "",
		k8sClient:      k8sClient,
	}
}

func (s *SysfsStorageInfoProvider) getNodeTemplate() string {
	if s.k8sClient == nil {
		return ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	node, err := s.k8sClient.CoreV1().Nodes().Get(
		ctx,
		s.nodeName,
		metav1.GetOptions{},
	)
	if err != nil {
		s.log.Warnf("failed to get node %s: %v", s.nodeName, err)
		return ""
	}

	return node.Labels["scheduling.cast.ai/node-template"]
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
		Devices:      s.getBackingDevices(partition.Device),
		NodeName:     s.nodeName,
		NodeTemplate: s.getNodeTemplate(),
		MountPoint:   partition.Mountpoint,
		TotalSize:    safeUint64ToInt64(usage.Total),
		UsedSpace:    safeUint64ToInt64(usage.Used),
		Timestamp:    timestamp,
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

// getLVMDMDevice resolves LVM logical volumes to their dm device.
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

func (s *SysfsStorageInfoProvider) buildBlockDeviceMetric(blockName string, stat disk.IOCountersStat, timestamp time.Time) BlockDeviceMetrics {
	diskUsage, err := s.getDeviceSize(blockName)
	if err != nil {
		s.log.Warnf("failed to get disk usage for %s: %v", blockName, err)
		diskUsage = 0
	}

	physicalDevices := s.resolvePhysicalDevices(blockName)

	return BlockDeviceMetrics{
		Name:            blockName,
		NodeName:        s.nodeName,
		NodeTemplate:    s.getNodeTemplate(),
		PhysicalDevices: physicalDevices,
		ReadIOPS:        safeUint64ToInt64(stat.ReadCount),
		WriteIOPS:       safeUint64ToInt64(stat.WriteCount),
		ReadThroughput:  float64(stat.ReadBytes),
		WriteThroughput: float64(stat.WriteBytes),
		Size:            diskUsage,
		Timestamp:       timestamp,
	}
}

func (s *SysfsStorageInfoProvider) getDeviceSize(deviceName string) (int64, error) {
	devicePath := fmt.Sprintf("%s/sys/block/%s/size", s.sysBlockPrefix, deviceName)
	if sectors, err := s.getDeviceSectorCount(devicePath); err == nil && sectors > 0 {
		return sectors * sectorSizeBytes, nil
	}

	if sectors, err := s.getPartitionSectorCount(deviceName); err == nil && sectors > 0 {
		return sectors * sectorSizeBytes, nil
	}

	return 0, fmt.Errorf("failed to get size for device %s", deviceName)
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
	blockDir := s.sysBlockPrefix + "/sys/block"
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
		if sectors, err := s.getDeviceSectorCount(partitionPath); err == nil && sectors > 0 {
			return sectors, nil
		}
	}

	return 0, fmt.Errorf("partition %s not found", deviceName)
}

func (s *SysfsStorageInfoProvider) getBlockSlaves(blockName string) ([]string, error) {
	slavesPath := fmt.Sprintf("%s/sys/block/%s/slaves", s.sysBlockPrefix, blockName)
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

func calculateBlockDeviceRates(current *BlockDeviceMetrics, prev *BlockDeviceMetrics, timeDiff float64) {
	current.ReadThroughput = (current.ReadThroughput - prev.ReadThroughput) / timeDiff
	current.WriteThroughput = (current.WriteThroughput - prev.WriteThroughput) / timeDiff
	current.ReadIOPS = int64(float64(current.ReadIOPS-prev.ReadIOPS) / timeDiff)
	current.WriteIOPS = int64(float64(current.WriteIOPS-prev.WriteIOPS) / timeDiff)
}
