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

// TODO: order functions in calude
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

// TODO small letter
func (c *SysfsStorageInfoProvider) BuildFilesystemMetrics(timestamp time.Time) ([]FilesystemMetrics, error) {
	partitions, err := c.diskClient.Partitions(false) // false = only physical devices
	if err != nil {
		return nil, fmt.Errorf("failed to get partitions: %w", err)
	}

	filesystemMetrics := make([]FilesystemMetrics, 0, len(partitions))
	for _, partition := range partitions {
		c.log.Infof("partition m: %s d: %s", partition.Mountpoint, partition.Device)
		metric, err := c.buildFilesystemMetric(partition, timestamp)
		if err != nil {
			c.log.Warnf("failed to build file system metric: %v", err)
			continue
		}
		filesystemMetrics = append(filesystemMetrics, *metric)
	}

	c.log.Debugf("collected %d filesystem metrics", len(filesystemMetrics))
	return filesystemMetrics, nil
}

func (c *SysfsStorageInfoProvider) buildFilesystemMetric(partition disk.PartitionStat, timestamp time.Time) (*FilesystemMetrics, error) {
	fileSystemPath := c.hostRootPath + partition.Mountpoint
	usage, err := c.diskClient.Usage(fileSystemPath)
	if err != nil {
		return nil, err
	}
	devices := c.resolveDeviceHierarchy(partition.Device)

	return &FilesystemMetrics{
		Devices:    devices,
		NodeName:   c.nodeName,
		MountPoint: partition.Mountpoint,
		TotalSize:  safeUint64ToInt64(usage.Total),
		UsedSpace:  safeUint64ToInt64(usage.Used),
		Timestamp:  timestamp,
	}, nil
}

// resolveDeviceHierarchy resolves a device to its underlying physical devices.
// Input examples: "/dev/mapper/vg-lv", "/dev/dm-0", "/dev/sda1"
// Output examples: ["/dev/sda5", "/dev/sdb1"] or ["/dev/sda1"]
func (c *SysfsStorageInfoProvider) resolveDeviceHierarchy(device string) []string {
	c.log.Infof("resolveDeviceHierarchy: device: %s", device)

	if slaves := c.getLVMSlaves(device); len(slaves) > 0 {
		return slaves
	}

	deviceName := strings.TrimPrefix(device, c.hostRootPath+"/dev/") //TODO: check if it still works
	c.log.Infof("resolveDeviceHierarchy: deviceName: %s", deviceName)
	if slaves := c.getUnderlyingDevices(deviceName); len(slaves) > 0 {
		return slaves
	}

	return []string{device}
}

// getLVMSlaves resolves LVM logical volumes to their underlying physical devices.
// It handles the symlink chain: /dev/mapper/vg-lv → /dev/dm-X → /sys/block/dm-X/slaves/ → [sdf, sdg]
func (c *SysfsStorageInfoProvider) getLVMSlaves(device string) []string {
	if !strings.HasPrefix(device, c.hostRootPath+"/dev/mapper/") { // TODO check if it works
		return nil
	}
	hostMapperPath := c.hostRootPath + device

	linkTarget, err := os.Readlink(hostMapperPath)
	if err != nil {
		c.log.Debugf("symlink resolution failed for %s: %v", device, err)
		return nil
	}
	c.log.Infof("resolveDeviceHierarchy: linkTarget: %s", linkTarget)

	resolvedDeviceName := filepath.Base(linkTarget)
	c.log.Infof("resolveDeviceHierarchy: resolvedDeviceName: %s", resolvedDeviceName)

	slaves := c.getUnderlyingDevices(resolvedDeviceName)
	c.log.Debugf("found %d underlying devices for LVM %s: %v", len(slaves), device, slaves)

	return slaves
}

func (c *SysfsStorageInfoProvider) getUnderlyingDevices(deviceName string) []string {
	slavesPath := fmt.Sprintf("%s/sys/block/%s/slaves", c.sysBlockPrefix, deviceName)

	exists, err := c.deviceExists(slavesPath)
	if err != nil || !exists {
		return []string{}
	}

	slaves, err := c.getBlockSlaves(deviceName)
	if err != nil {
		c.log.Debugf("no slaves directory found for %s: %v", deviceName, err)
		return []string{}
	}

	var fullPaths []string
	for _, slaveName := range slaves {
		fullPaths = append(fullPaths, "/dev/"+slaveName)
		c.log.Debugf("found slave device %s for parent %s", slaveName, deviceName)
	}

	c.log.Debugf("%d slaves discovered for %s", len(fullPaths), deviceName)
	return fullPaths
}

func (c *SysfsStorageInfoProvider) resolvePhysicalDevices(blockName string) []string {
	visited := make(map[string]bool)
	// TODO: check if recursivness is actually needed with claude
	physicalDevices := c.getPhysicalDevicesRecursive(blockName, visited)

	if len(physicalDevices) == 0 {
		return []string{"/dev/" + blockName}
	}

	return c.deduplicateDevices(physicalDevices)
}

func (c *SysfsStorageInfoProvider) getPhysicalDevicesRecursive(blockName string, visited map[string]bool) []string {
	if visited[blockName] {
		c.log.Warnf("circular dependency detected for device %s", blockName)
		return []string{"/dev/" + blockName}
	}
	visited[blockName] = true

	slaves, err := c.getBlockSlaves(blockName)
	if err != nil {
		c.log.Debugf("cannot read slaves for %s: %v", blockName, err)
		return nil
	}

	var allPhysicalDevices []string
	for _, slave := range slaves {
		slavePhysical := c.getPhysicalDevicesRecursive(slave, visited)
		allPhysicalDevices = append(allPhysicalDevices, slavePhysical...)
	}

	return allPhysicalDevices
}

func (c *SysfsStorageInfoProvider) deduplicateDevices(devices []string) []string {
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

// safeUint64ToInt64 safely converts uint64 to int64, clamping to MaxInt64 if overflow would occur
func safeUint64ToInt64(val uint64) int64 {
	if val > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(val)
}

func (c *SysfsStorageInfoProvider) BuildBlockDeviceMetrics(timestamp time.Time) ([]BlockDeviceMetrics, error) {
	ioStats, err := c.diskClient.IOCounters()
	if err != nil {
		return nil, fmt.Errorf("failed to get IO counters: %w", err)
	}

	blockMetrics := make([]BlockDeviceMetrics, 0, len(ioStats))

	for blockName, stat := range ioStats {
		c.log.Infof("getBlockDeviceMetrics: blockName: %s", blockName)

		current := c.buildBlockDeviceMetric(blockName, stat, c.nodeName, timestamp)

		prev, exists := c.storageState.blockDevices[current.Name]
		if exists {
			timeDiff := current.Timestamp.Sub(prev.Timestamp).Seconds()
			if timeDiff > 0 {
				calculateBlockDeviceRates(&current, prev, timeDiff)
				blockMetrics = append(blockMetrics, current)
			}
		}

		c.storageState.blockDevices[current.Name] = &current
	}

	return blockMetrics, nil
}

func (c *SysfsStorageInfoProvider) buildBlockDeviceMetric(blockName string, stat disk.IOCountersStat, nodeName string, timestamp time.Time) BlockDeviceMetrics {
	diskUsage, err := c.getDeviceSize(blockName)
	if err != nil {
		c.log.Warnf("failed to get disk usage for %s: %v", blockName, err)
		diskUsage = 0
	}

	physicalDevices := c.resolvePhysicalDevices(blockName)

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

func (p *SysfsStorageInfoProvider) deviceExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
