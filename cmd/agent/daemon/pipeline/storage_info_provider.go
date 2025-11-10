package pipeline

import (
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/elastic/go-freelru"
	"github.com/samber/lo"
	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding/gzip"

	kubepb "github.com/castai/kvisor/api/v1/kube"
	"github.com/castai/kvisor/pkg/logging"
)

const sectorSizeBytes = 512
const hostPathRoot = "/proc/1/root"

// BlockDeviceMetric represents enhanced block device metrics with accurate sector sizes
type BlockDeviceMetric struct {
	Name         string    `avro:"name"`
	NodeName     string    `avro:"node_name"`
	NodeTemplate *string   `avro:"node_template"`
	Path         string    `avro:"path"`
	SizeBytes    *int64    `avro:"size_bytes"`
	DiskType     string    `avro:"disk_type"`    // HDD, SSD
	PartitionOf  string    `avro:"partition_of"` // parent device for partitions
	Holders      []string  `avro:"holders"`      // devices using this device
	IsVirtual    bool      `avro:"is_virtual"`   // dm-* or md* devices
	RaidLevel    string    `avro:"raid_level"`   // raid0, raid1, raid5, etc

	ReadIOPS             float64   `avro:"read_iops"`
	WriteIOPS            float64   `avro:"write_iops"`
	ReadThroughputBytes  float64   `avro:"read_throughput_bytes"`
	WriteThroughputBytes float64   `avro:"write_throughput_bytes"`
	ReadLatencyMs        float64   `avro:"read_latency_ms"`
	WriteLatencyMs       float64   `avro:"write_latency_ms"`
	InFlightRequests     int64     `avro:"in_flight_requests"`
	AvgQueueDepth        float64   `avro:"avg_queue_depth"`
	Utilization          float64   `avro:"utilization"`
	Timestamp            time.Time `avro:"ts"`

	// Internal fields for calculation (raw cumulative counters)
	logicalSectorSize  uint64
	readIOs            uint64
	writeIOs           uint64
	readSectors        uint64
	writeSectors       uint64
	readTicks          uint64
	writeTicks         uint64
	ioTicks            uint64
	timeInQueue        uint64
}

type FilesystemMetric struct {
	Devices      []string  `avro:"devices"`
	NodeName     string    `avro:"node_name"`
	NodeTemplate *string   `avro:"node_template"`
	MountPoint   string    `avro:"mount_point"`
	Type         string    `avro:"type"`    // Filesystem type (ext4, xfs, btrfs, etc.)
	Options      []string  `avro:"options"` // Mount options
	TotalBytes   *int64    `avro:"total_bytes"`
	UsedBytes    *int64    `avro:"used_bytes"`
	TotalInodes  *int64    `avro:"total_inodes"`
	UsedInodes   *int64    `avro:"used_inodes"`
	Timestamp    time.Time `avro:"ts"`
}

// NodeStatsSummaryMetric represents node-level filesystem statistics from kubelet
type NodeStatsSummaryMetric struct {
	NodeName             string    `avro:"node_name"`
	NodeTemplate         *string   `avro:"node_template"`
	ImageFsSizeBytes     *int64    `avro:"image_fs_size_bytes"`
	ImageFsUsedBytes     *int64    `avro:"image_fs_used_bytes"`
	ContainerFsSizeBytes *int64    `avro:"container_fs_size_bytes"`
	ContainerFsUsedBytes *int64    `avro:"container_fs_used_bytes"`
	Timestamp            time.Time `avro:"ts"`
}

type storageMetricsState struct {
	blockDevices map[string]*BlockDeviceMetric
	filesystems  map[string]*FilesystemMetric
}

type StorageInfoProvider interface {
	BuildFilesystemMetrics(timestamp time.Time) ([]FilesystemMetric, error)
	BuildBlockDeviceMetrics(timestamp time.Time) ([]BlockDeviceMetric, error)
	CollectNodeStatsSummary(ctx context.Context) (*NodeStatsSummaryMetric, error)
}

type SysfsStorageInfoProvider struct {
	log            *logging.Logger
	storageState   *storageMetricsState
	nodeName       string
	clusterID      string
	hostRootPath   string
	sysBlockPrefix string
	kubeClient     kubepb.KubeAPIClient
	nodeCache      *freelru.SyncedLRU[string, *kubepb.Node]
}

func NewStorageInfoProvider(log *logging.Logger, kubeClient kubepb.KubeAPIClient, clusterID string) (StorageInfoProvider, error) {
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
		nodeName:       os.Getenv("NODE_NAME"),
		clusterID:      clusterID,
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
		return nil, nil
	}

	// Try the scheduling label first (current standard)
	if nodeTemplate, exists := node.Labels["scheduling.cast.ai/node-template"]; exists {
		return &nodeTemplate, nil
	}

	// Fallback to provisioner label (legacy)
	if nodeTemplate, exists := node.Labels["provisioner.cast.ai/node-template"]; exists {
		return &nodeTemplate, nil
	}

	return nil, nil
}

// CollectNodeStatsSummary retrieves node stats summary from the controller and builds a metric
func (s *SysfsStorageInfoProvider) CollectNodeStatsSummary(ctx context.Context) (*NodeStatsSummaryMetric, error) {
	if s.kubeClient == nil {
		return nil, fmt.Errorf("kube client is not initialized")
	}

	// Get node stats summary from controller
	resp, err := s.kubeClient.GetNodeStatsSummary(ctx, &kubepb.GetNodeStatsSummaryRequest{
		NodeName: s.nodeName,
	}, grpc.UseCompressor(gzip.Name))
	if err != nil {
		return nil, fmt.Errorf("failed to get node stats summary for %s: %w", s.nodeName, err)
	}

	if resp == nil || resp.Node == nil {
		return nil, fmt.Errorf("empty node stats response for %s", s.nodeName)
	}

	// Get node template
	nodeTemplate, err := s.getNodeTemplate()
	if err != nil {
		s.log.Warnf("failed to get node template: %v", err)
		// Don't fail the whole collection if node template lookup fails
		nodeTemplate = nil
	}

	// Extract filesystem metrics
	metric := &NodeStatsSummaryMetric{
		NodeName:     s.nodeName,
		NodeTemplate: nodeTemplate,
		Timestamp:    time.Now(),
	}

	if resp.Node.Runtime != nil {
		if resp.Node.Runtime.ImageFs != nil {
			if resp.Node.Runtime.ImageFs.CapacityBytes > 0 {
				metric.ImageFsSizeBytes = lo.ToPtr(safeUint64ToInt64(resp.Node.Runtime.ImageFs.CapacityBytes))
			}
			if resp.Node.Runtime.ImageFs.UsedBytes > 0 {
				metric.ImageFsUsedBytes = lo.ToPtr(safeUint64ToInt64(resp.Node.Runtime.ImageFs.UsedBytes))
			}
		}
		if resp.Node.Runtime.ContainerFs != nil {
			if resp.Node.Runtime.ContainerFs.CapacityBytes > 0 {
				metric.ContainerFsSizeBytes = lo.ToPtr(safeUint64ToInt64(resp.Node.Runtime.ContainerFs.CapacityBytes))
			}
			if resp.Node.Runtime.ContainerFs.UsedBytes > 0 {
				metric.ContainerFsUsedBytes = lo.ToPtr(safeUint64ToInt64(resp.Node.Runtime.ContainerFs.UsedBytes))
			}
		}
	}

	return metric, nil
}

func (s *SysfsStorageInfoProvider) BuildFilesystemMetrics(timestamp time.Time) ([]FilesystemMetric, error) {
	// Read mount information from /proc/1/mountinfo
	mounts, err := readMountInfo("/proc/1/mountinfo")
	if err != nil {
		return nil, fmt.Errorf("failed to read mountinfo: %w", err)
	}

	filesystemMetrics := make([]FilesystemMetric, 0, len(mounts))
	for _, mount := range mounts {
		metric := s.buildFilesystemMetric(mount, timestamp)
		filesystemMetrics = append(filesystemMetrics, metric)
	}

	return filesystemMetrics, nil
}

func (s *SysfsStorageInfoProvider) buildFilesystemMetric(mount mountInfo, timestamp time.Time) FilesystemMetric {
	// Construct the path from host's root to access the filesystem
	fileSystemPath := s.hostRootPath + mount.MountPoint

	// Get filesystem statistics using syscall.Statfs
	sizeBytes, usedBytes, totalInodes, usedInodes, statsErr := getFilesystemStats(fileSystemPath)
	if statsErr != nil {
		s.log.Warnf("failed to get filesystem stats for %s: %v", mount.MountPoint, statsErr)
	}

	nodeTemplate, err := s.getNodeTemplate()
	if err != nil {
		s.log.Warnf("failed to get node template for %s: %v", mount.MountPoint, err)
	}

	// Convert to pointers (nil if stats failed)
	var totalBytesPtr, usedBytesPtr *int64
	var totalInodesPtr, usedInodesPtr *int64

	if statsErr == nil {
		totalBytesPtr = &sizeBytes
		usedBytesPtr = &usedBytes
		totalInodesPtr = &totalInodes
		usedInodesPtr = &usedInodes
	}

	return FilesystemMetric{
		Devices:      s.getBackingDevices(mount.Device),
		NodeName:     s.nodeName,
		NodeTemplate: nodeTemplate,
		MountPoint:   mount.MountPoint,
		Type:         mount.FsType,
		Options:      mount.Options,
		TotalBytes:   totalBytesPtr,
		UsedBytes:    usedBytesPtr,
		TotalInodes:  totalInodesPtr,
		UsedInodes:   usedInodesPtr,
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

func (s *SysfsStorageInfoProvider) BuildBlockDeviceMetrics(timestamp time.Time) ([]BlockDeviceMetric, error) {
	// Read stats from /proc/diskstats
	diskStats, err := readProcDiskStats()
	if err != nil {
		return nil, fmt.Errorf("failed to read disk stats: %w", err)
	}

	blockMetrics := make([]BlockDeviceMetric, 0, len(diskStats))

	for deviceName, stats := range diskStats {
		current := s.buildBlockDeviceMetric(deviceName, stats, timestamp)

		prev, exists := s.storageState.blockDevices[current.Name]
		if exists {
			timeDiff := current.Timestamp.Sub(prev.Timestamp).Seconds()
			if timeDiff > 0 {
				s.calculateBlockDeviceRates(&current, prev, timeDiff)
				blockMetrics = append(blockMetrics, current)
			}
		}

		s.storageState.blockDevices[current.Name] = &current
	}

	return blockMetrics, nil
}

func (s *SysfsStorageInfoProvider) buildBlockDeviceMetric(blockName string, stats DiskStats, timestamp time.Time) BlockDeviceMetric {
	// Get device metadata
	diskType := s.getDiskType(blockName)

	// Check if this is a partition to find parent device
	partitionOf := ""
	deviceType := s.getDeviceType(blockName)
	if deviceType == "partition" {
		partitionOf = s.getPartitionParent(blockName)
	}

	holders := s.getHolders(blockName)
	raidLevel := s.getRaidLevel(blockName)
	logicalSectorSize := s.getLogicalSectorSize(blockName)

	diskSize, err := s.getDeviceSize(blockName)
	if err != nil {
		s.log.Debugf("failed to get disk size for %s: %v", blockName, err)
	}

	nodeTemplate, err := s.getNodeTemplate()
	if err != nil {
		s.log.Debugf("failed to get node template for %s: %v", blockName, err)
	}

	return BlockDeviceMetric{
		Name:               blockName,
		NodeName:           s.nodeName,
		NodeTemplate:       nodeTemplate,
		Path:               filepath.Join("/dev", blockName),
		SizeBytes:          diskSize,
		DiskType:           diskType,
		PartitionOf:        partitionOf,
		Holders:            holders,
		IsVirtual:          isVirtualDevice(blockName),
		RaidLevel:          raidLevel,
		Timestamp:          timestamp,
		InFlightRequests:   int64(stats.InFlight),

		// Internal fields for delta calculation
		logicalSectorSize:  logicalSectorSize,
		readIOs:            stats.ReadIOs,
		writeIOs:           stats.WriteIOs,
		readSectors:        stats.ReadSectors,
		writeSectors:       stats.WriteSectors,
		readTicks:          stats.ReadTicks,
		writeTicks:         stats.WriteTicks,
		ioTicks:            stats.IOTicks,
		timeInQueue:        stats.TimeInQueue,
	}
}

func (s *SysfsStorageInfoProvider) calculateBlockDeviceRates(current *BlockDeviceMetric, prev *BlockDeviceMetric, timeDiff float64) {
	if timeDiff <= 0 {
		return
	}

	// Calculate deltas
	deltaReadIOs := float64(current.readIOs - prev.readIOs)
	deltaWriteIOs := float64(current.writeIOs - prev.writeIOs)
	deltaReadSectors := float64(current.readSectors - prev.readSectors)
	deltaWriteSectors := float64(current.writeSectors - prev.writeSectors)
	deltaReadTicks := float64(current.readTicks - prev.readTicks)
	deltaWriteTicks := float64(current.writeTicks - prev.writeTicks)
	deltaIOTicks := float64(current.ioTicks - prev.ioTicks)
	deltaTimeInQueue := float64(current.timeInQueue - prev.timeInQueue)

	// Calculate rates
	current.ReadIOPS = deltaReadIOs / timeDiff
	current.WriteIOPS = deltaWriteIOs / timeDiff

	// Use actual logical sector size for throughput
	sectorSize := float64(current.logicalSectorSize)
	current.ReadThroughputBytes = (deltaReadSectors * sectorSize) / timeDiff
	current.WriteThroughputBytes = (deltaWriteSectors * sectorSize) / timeDiff

	// Calculate latencies (average time per operation in milliseconds)
	current.ReadLatencyMs = safeDiv(deltaReadTicks, deltaReadIOs)
	current.WriteLatencyMs = safeDiv(deltaWriteTicks, deltaWriteIOs)

	// Calculate average queue depth
	current.AvgQueueDepth = safeDiv(deltaTimeInQueue, timeDiff*1000.0)

	// Calculate utilization (fraction of time with I/O operations, 0-1)
	current.Utilization = safeDiv(deltaIOTicks, timeDiff*1000.0)
}

// getDeviceSize - reads from /sys/block/<device>/size or /sys/block/<parent>/<partition>/size
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

func isLVMDevice(deviceName string) bool {
	return strings.HasPrefix(deviceName, "dm-")
}

func isRAIDDevice(deviceName string) bool {
	return strings.HasPrefix(deviceName, "md")
}

func isVirtualDevice(deviceName string) bool {
	return isLVMDevice(deviceName) || isRAIDDevice(deviceName)
}

func (s *SysfsStorageInfoProvider) getDeviceType(blockName string) string {
	devicePath := filepath.Join(s.sysBlockPrefix, "sys", "block", blockName)

	// Check if device exists in /sys/block (top-level device)
	// Source: /sys/block/<device>/
	if _, err := os.Stat(devicePath); os.IsNotExist(err) {
		return "partition"
	}

	// Check for device-mapper (LVM)
	// Source: /sys/block/<device>/dm/uuid
	if isLVMDevice(blockName) {
		uuidPath := filepath.Join(devicePath, "dm", "uuid")
		if uuid, err := os.ReadFile(uuidPath); err == nil {
			if strings.HasPrefix(string(uuid), "LVM-") {
				return "lvm"
			}
		}
		return "device-mapper"
	}

	// Check for RAID
	// Source: /sys/block/<device>/md/
	if isRAIDDevice(blockName) {
		mdPath := filepath.Join(devicePath, "md")
		if _, err := os.Stat(mdPath); err == nil {
			return "raid"
		}
	}

	// Check for virtual devices with slaves
	// Source: /sys/block/<device>/slaves/
	slavesPath := filepath.Join(devicePath, "slaves")
	if entries, err := os.ReadDir(slavesPath); err == nil && len(entries) > 0 {
		return "virtual"
	}

	return "physical"
}

// getPartitionParent - reads from /sys/block/<parent>/<partition>/
func (s *SysfsStorageInfoProvider) getPartitionParent(partition string) string {
	blockDir := filepath.Join(s.sysBlockPrefix, "sys", "block")
	entries, err := os.ReadDir(blockDir)
	if err != nil {
		return ""
	}

	for _, entry := range entries {
		partPath := filepath.Join(blockDir, entry.Name(), partition)
		if _, err := os.Stat(partPath); err == nil {
			return entry.Name()
		}
	}

	return ""
}

// getRaidLevel - reads from /sys/block/<device>/md/level
func (s *SysfsStorageInfoProvider) getRaidLevel(deviceName string) string {
	if !isRAIDDevice(deviceName) {
		return ""
	}

	levelPath := filepath.Join(s.sysBlockPrefix, "sys", "block", deviceName, "md", "level")
	data, err := os.ReadFile(levelPath)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(data))
}

// getLogicalSectorSize - reads from /sys/block/<device>/queue/logical_block_size
func (s *SysfsStorageInfoProvider) getLogicalSectorSize(deviceName string) uint64 {
	sizePath := filepath.Join(s.sysBlockPrefix, "sys", "block", deviceName, "queue", "logical_block_size")
	data, err := os.ReadFile(sizePath)
	if err != nil {
		return 512 // fallback to default
	}

	size, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 512
	}

	return size
}

// getDiskType - reads from /sys/block/<device>/queue/rotational
func (s *SysfsStorageInfoProvider) getDiskType(deviceName string) string {
	rotPath := filepath.Join(s.sysBlockPrefix, "sys", "block", deviceName, "queue", "rotational")
	data, err := os.ReadFile(rotPath)
	if err != nil {
		return ""
	}

	rotational := strings.TrimSpace(string(data))
	if rotational == "0" {
		return "SSD"
	}
	return "HDD"
}

// getHolders - reads from /sys/block/<device>/holders/
func (s *SysfsStorageInfoProvider) getHolders(deviceName string) []string {
	holdersPath := filepath.Join(s.sysBlockPrefix, "sys", "block", deviceName, "holders")
	entries, err := os.ReadDir(holdersPath)
	if err != nil {
		return nil
	}

	var holders []string
	for _, entry := range entries {
		holders = append(holders, entry.Name())
	}

	return holders
}

func safeUint64ToInt64(val uint64) int64 {
	if val > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(val)
}

func safeDiv(numerator, denominator float64) float64 {
	if denominator == 0 {
		return 0
	}
	return numerator / denominator
}

// mountInfo represents a parsed line from /proc/1/mountinfo
type mountInfo struct {
	Device      string
	MountPoint  string
	FsType      string
	Options     []string
	MajorMinor  string
}

// readMountInfo - reads from /proc/1/mountinfo
func readMountInfo(mountInfoPath string) ([]mountInfo, error) {
	if mountInfoPath == "" {
		mountInfoPath = "/proc/1/mountinfo"
	}

	data, err := os.ReadFile(mountInfoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", mountInfoPath, err)
	}

	var mounts []mountInfo
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		mount, err := parseMountInfoLine(line)
		if err != nil {
			// Skip unsupported or malformed lines
			continue
		}
		if mount != nil {
			mounts = append(mounts, *mount)
		}
	}

	return mounts, nil
}

// parseMountInfoLine parses a single line from /proc/1/mountinfo
// Format: <mount id> <parent id> <major:minor> <root> <mount point> <mount options> <optional fields> - <fs type> <mount source> <super options>
func parseMountInfoLine(line string) (*mountInfo, error) {
	// The " - " separator splits the line into two parts
	parts := strings.Split(line, " - ")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid mountinfo format: missing separator")
	}

	left := strings.Fields(parts[0])
	right := strings.Fields(parts[1])

	if len(left) < 6 || len(right) < 2 {
		return nil, fmt.Errorf("insufficient fields in mountinfo line")
	}

	majorMinor := left[2]
	mountPoint := left[4]
	mountOptions := strings.Split(left[5], ",")
	fsType := right[0]
	device := right[1]

	// Filter to only supported filesystem types
	if !isSupportedFilesystem(fsType) {
		return nil, nil // Not an error, just not supported
	}

	return &mountInfo{
		Device:     device,
		MountPoint: mountPoint,
		FsType:     fsType,
		Options:    mountOptions,
		MajorMinor: majorMinor,
	}, nil
}

func isSupportedFilesystem(fsType string) bool {
	switch fsType {
	case "ext4", "xfs", "btrfs", "ext3", "ext2":
		return true
	default:
		return false
	}
}

// getFilesystemStats - takes data from syscall.Statfs() system call
func getFilesystemStats(mountPoint string) (sizeBytes, usedBytes int64, totalInodes, usedInodes int64, err error) {
	var stat syscall.Statfs_t
	err = syscall.Statfs(mountPoint, &stat)
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("failed to statfs %s: %w", mountPoint, err)
	}

	blockSize := uint64(stat.Bsize)

	// Calculate block-based metrics
	totalBlocks := stat.Blocks
	freeBlocks := stat.Bfree
	usedBlocks := totalBlocks - freeBlocks

	// Convert to bytes
	totalSizeBytes := totalBlocks * blockSize
	usedSpaceBytes := usedBlocks * blockSize

	// Inode statistics
	totalInodesVal := stat.Files
	usedInodesVal := totalInodesVal - stat.Ffree

	return safeUint64ToInt64(totalSizeBytes),
		safeUint64ToInt64(usedSpaceBytes),
		safeUint64ToInt64(totalInodesVal),
		safeUint64ToInt64(usedInodesVal),
		nil
}

