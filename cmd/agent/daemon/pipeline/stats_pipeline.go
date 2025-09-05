package pipeline

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/disk"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/metrics"
	"github.com/castai/kvisor/pkg/cgroup"
	"github.com/castai/kvisor/pkg/containers"
)

const hostRootPath = "/proc/1/root"
const sectorSizeBytes = 512

// DeviceInfoProvider abstracts system device information operations for testability
type DeviceInfoProvider interface {
	GetDeviceSize(deviceName string) (int64, error)
	ListBlockDevices() ([]string, error)
	GetDeviceSlaves(deviceName string) ([]string, error)
	FindPartitionParent(deviceName string) (string, error)
	DeviceExists(path string) (bool, error)
}

// SysfsDeviceInfoProvider implements DeviceInfoProvider using Linux sysfs filesystem operations
type SysfsDeviceInfoProvider struct{}

// NewSysfsDeviceInfoProvider creates a new SysfsDeviceInfoProvider instance
func NewSysfsDeviceInfoProvider() *SysfsDeviceInfoProvider {
	return &SysfsDeviceInfoProvider{}
}

func (p *SysfsDeviceInfoProvider) GetDeviceSize(deviceName string) (int64, error) {
	devicePath := fmt.Sprintf("/sys/block/%s/size", deviceName)
	if sectors, err := p.getDeviceSectorCount(devicePath); err == nil && sectors > 0 {
		return sectors * sectorSizeBytes, nil
	}

	if sectors, err := p.getPartitionSectorCount(deviceName); err == nil && sectors > 0 {
		return sectors * sectorSizeBytes, nil
	}

	return 0, fmt.Errorf("failed to get size for device %s", deviceName)
}

func (p *SysfsDeviceInfoProvider) getDeviceSectorCount(devicePath string) (int64, error) {
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

func (p *SysfsDeviceInfoProvider) getPartitionSectorCount(deviceName string) (int64, error) {
	blockDir := "/sys/block"
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

func (p *SysfsDeviceInfoProvider) ListBlockDevices() ([]string, error) {
	entries, err := os.ReadDir("/sys/block")
	if err != nil {
		return nil, err
	}

	var devices []string
	for _, entry := range entries {
		if entry.IsDir() {
			devices = append(devices, entry.Name())
		}
	}

	return devices, nil
}

func (p *SysfsDeviceInfoProvider) GetDeviceSlaves(deviceName string) ([]string, error) {
	slavesPath := fmt.Sprintf("/sys/block/%s/slaves", deviceName)
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

func (p *SysfsDeviceInfoProvider) FindPartitionParent(deviceName string) (string, error) {
	blockDevices, err := p.ListBlockDevices()
	if err != nil {
		return "", err
	}

	for _, parentDeviceName := range blockDevices {
		partitionPath := fmt.Sprintf("/sys/block/%s/%s", parentDeviceName, deviceName)
		if _, err := os.Stat(partitionPath); err == nil {
			return parentDeviceName, nil
		}
	}

	return "", fmt.Errorf("parent not found for partition %s", deviceName)
}

func (p *SysfsDeviceInfoProvider) DeviceExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

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

type containerStatsGroup struct {
	pb          *castaipb.ContainerStats
	prevCpuStat *castaipb.CpuStats
	prevMemStat *castaipb.MemoryStats
	prevIOStat  *castaipb.IOStats
	changed     bool
	updatedAt   time.Time
}

func (g *containerStatsGroup) updatePrevCgroupStats(cgStats cgroup.Stats) {
	g.prevCpuStat = cgStats.CpuStats
	g.prevMemStat = cgStats.MemoryStats
	g.prevIOStat = cgStats.IOStats
}

type nodeScrapePoint struct {
	nodeName string
	cpuStat  *castaipb.CpuStats
	memStat  *castaipb.MemoryStats
	ioStat   *castaipb.IOStats

	prevCpuStat *castaipb.CpuStats
	prevMemStat *castaipb.MemoryStats
	prevIOStat  *castaipb.IOStats
}

type storageMetricsState struct {
	blockDevices map[string]*BlockDeviceMetrics
	filesystems  map[string]*FilesystemMetrics
}

func (c *Controller) runStatsPipeline(ctx context.Context) error {
	c.log.Info("running stats pipeline")
	defer c.log.Info("stats pipeline done")

	ticker := time.NewTicker(c.cfg.Stats.ScrapeInterval)
	defer ticker.Stop()

	nodeStats := &nodeScrapePoint{
		nodeName: c.nodeName,
	}
	containerStatsGroups := c.containerStatsGroups
	batchState := newDataBatchStats()

	send := func() {
		items := make([]*castaipb.DataBatchItem, 0, batchState.totalItems)
		for _, group := range containerStatsGroups {
			if !group.changed {
				continue
			}
			items = append(items, &castaipb.DataBatchItem{
				Data: &castaipb.DataBatchItem_ContainerStats{
					ContainerStats: group.pb,
				},
			})
		}
		if nodeStats.cpuStat != nil {
			items = append(items, &castaipb.DataBatchItem{
				Data: &castaipb.DataBatchItem_NodeStats{
					NodeStats: &castaipb.NodeStats{
						NodeName:    nodeStats.nodeName,
						CpuStats:    nodeStats.cpuStat,
						MemoryStats: nodeStats.memStat,
						IoStats:     nodeStats.ioStat,
					},
				},
			})
		}
		// Skip if no changes.
		if len(items) == 0 {
			return
		}
		c.sendDataBatch("container stats scrape", metrics.PipelineStats, items)
		batchState.reset()
		now := time.Now()
		for key, group := range containerStatsGroups {
			// Delete the inactive group.
			if group.updatedAt.Add(time.Minute).Before(now) {
				delete(containerStatsGroups, key)
				c.log.Debugf("deleted inactive container stats group, container=%s(%s)", group.pb.ContainerName, group.pb.ContainerId)
				continue
			}
			group.changed = false
			group.pb.FilesAccessStats = nil
		}
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			start := time.Now()
			c.scrapeNodeStats(nodeStats, batchState)
			c.scrapeContainersStats(containerStatsGroups, batchState)
			if c.cfg.Stats.StorageEnabled {
				c.collectStorageMetrics()
			}
			send()
			c.log.Debugf("stats exported, duration=%v", time.Since(start))
		}
	}
}

func (c *Controller) scrapeContainersStats(groups map[uint64]*containerStatsGroup, batchState *dataBatchStats) {
	conts := c.containersClient.ListContainers(func(cont *containers.Container) bool {
		return cont.Err == nil && cont.Cgroup != nil && cont.Name != ""
	})

	c.log.Infof("scraping stats from %d containers", len(conts))
	for _, cont := range conts {
		group, found := groups[cont.CgroupID]
		if !found {
			group = c.createNewContainerStatsGroup(cont)
			groups[cont.CgroupID] = group
		}

		if c.cfg.Stats.Enabled {
			c.scrapeContainerCgroupStats(group, cont, batchState)
		}
	}

	if c.cfg.Stats.FileAccessEnabled {
		c.scrapeContainersFileAccessStats(groups)
	}
}

func (c *Controller) createNewContainerStatsGroup(cont *containers.Container) *containerStatsGroup {
	group := &containerStatsGroup{
		updatedAt: time.Now(),
		pb: &castaipb.ContainerStats{
			Namespace:     cont.PodNamespace,
			PodName:       cont.PodName,
			ContainerName: cont.Name,
			PodUid:        cont.PodUID,
			ContainerId:   cont.ID,
			NodeName:      c.nodeName,
			CgroupId:      cont.CgroupID,
		},
	}
	if podInfo, ok := c.getPodInfo(cont.PodUID); ok {
		group.pb.WorkloadName = podInfo.WorkloadName
		group.pb.WorkloadKind = workloadKindString(podInfo.WorkloadKind)
		group.pb.WorkloadUid = podInfo.WorkloadUid
	}
	return group
}

func (c *Controller) scrapeContainerCgroupStats(group *containerStatsGroup, cont *containers.Container, stats *dataBatchStats) {
	cgStats, err := c.containersClient.GetCgroupStats(cont)
	if err != nil {
		if c.log.IsEnabled(slog.LevelDebug) {
			var cgPath string
			if cont.Cgroup != nil {
				cgPath = cont.Cgroup.Path
			}
			c.log.Warnf("getting cgroup stats, container=%s(%s), cgroup_path=%s: %v", cont.Name, cont.ID, cgPath, err)
		}
		if !errors.Is(err, cgroup.ErrStatsNotFound) {
			metrics.AgentStatsScrapeErrorsTotal.WithLabelValues("container").Inc()
		}
		return
	}

	if group.prevCpuStat == nil {
		group.updatePrevCgroupStats(cgStats)
		// We need at least two scrapes for cgroup stats.
		return
	}

	group.changed = true
	group.updatedAt = time.Now()
	stats.sizeBytes += proto.Size(group.pb)
	stats.totalItems++

	group.pb.CpuStats = getCPUStatsDiff(group.prevCpuStat, cgStats.CpuStats)
	group.pb.MemoryStats = getMemoryStatsDiff(group.prevMemStat, cgStats.MemoryStats)
	group.pb.IoStats = getIOStatsDiff(group.prevIOStat, cgStats.IOStats)
	group.pb.PidsStats = cgStats.PidsStats

	group.updatePrevCgroupStats(cgStats)
}

func (c *Controller) scrapeNodeStats(nodeStats *nodeScrapePoint, stats *dataBatchStats) {
	if err := func() error {
		// For now, we only care about PSI related metrics on node.
		if !c.procHandler.PSIEnabled() {
			return nil
		}
		c.log.Debug("scraping node stats")

		cpuPSI, err := c.procHandler.GetPSIStats("cpu")
		if err != nil {
			return err
		}
		memStats, err := c.procHandler.GetMeminfoStats()
		if err != nil {
			return err
		}
		memoryPSI, err := c.procHandler.GetPSIStats("memory")
		if err != nil {
			return err
		}
		ioPSI, err := c.procHandler.GetPSIStats("io")
		if err != nil {
			return err
		}

		currCPU := &castaipb.CpuStats{Psi: cpuPSI}
		currMem := &castaipb.MemoryStats{
			Usage:         memStats.Usage,
			SwapOnlyUsage: memStats.SwapOnlyUsage,
			Psi:           memoryPSI,
		}
		currIO := &castaipb.IOStats{Psi: ioPSI}

		// We need at least 2 scrapes to calculate diffs.
		// Diffs are needed for always increasing counters only because we store them as deltas.
		// This includes cpu usage and psi total value.
		if nodeStats.prevCpuStat == nil {
			nodeStats.prevCpuStat = currCPU
			nodeStats.prevMemStat = currMem
			nodeStats.prevIOStat = currIO
			return nil
		}

		nodeStats.cpuStat = getCPUStatsDiff(nodeStats.prevCpuStat, currCPU)
		nodeStats.memStat = getMemoryStatsDiff(nodeStats.prevMemStat, currMem)
		nodeStats.ioStat = getIOStatsDiff(nodeStats.prevIOStat, currIO)
		nodeStats.prevCpuStat = currCPU
		nodeStats.prevMemStat = currMem
		nodeStats.prevIOStat = currIO
		stats.totalItems++

		return nil
	}(); err != nil {
		if c.log.IsEnabled(slog.LevelDebug) {
			c.log.Errorf("getting cgroup stats for node %q: %v", c.nodeName, err)
		}
		metrics.AgentStatsScrapeErrorsTotal.WithLabelValues("node").Inc()
		return
	}
}

func (c *Controller) scrapeContainersFileAccessStats(groups map[uint64]*containerStatsGroup) {
	keys, vals, err := c.tracer.CollectFileAccessStats()
	if err != nil {
		c.log.Errorf("collecting file access stats: %v", err)
		return
	}

	for i, key := range keys {
		val := vals[i]
		group, found := groups[key.CgroupId]
		if !found {
			continue
		}
		group.changed = true
		if group.pb.FilesAccessStats == nil {
			group.pb.FilesAccessStats = &castaipb.FilesAccessStats{}
		}
		group.pb.FilesAccessStats.Paths = append(group.pb.FilesAccessStats.Paths, unix.ByteSliceToString(val.Filepath[:]))
		group.pb.FilesAccessStats.Reads = append(group.pb.FilesAccessStats.Reads, val.Reads)
	}
}

func getCPUStatsDiff(prev, curr *castaipb.CpuStats) *castaipb.CpuStats {
	if prev == nil || curr == nil {
		return &castaipb.CpuStats{}
	}
	return &castaipb.CpuStats{
		TotalUsage:        curr.TotalUsage - prev.TotalUsage,
		UsageInKernelmode: curr.UsageInKernelmode - prev.UsageInKernelmode,
		UsageInUsermode:   curr.UsageInUsermode - prev.UsageInUsermode,
		ThrottledPeriods:  curr.ThrottledPeriods,
		ThrottledTime:     curr.ThrottledTime,
		Psi:               getPSIStatsDiff(prev.Psi, curr.Psi),
	}
}

func getMemoryStatsDiff(prev, curr *castaipb.MemoryStats) *castaipb.MemoryStats {
	if prev == nil || curr == nil {
		return &castaipb.MemoryStats{}
	}
	return &castaipb.MemoryStats{
		Cache:         curr.Cache,
		Usage:         curr.Usage,
		SwapOnlyUsage: curr.SwapOnlyUsage,
		Psi:           getPSIStatsDiff(prev.Psi, curr.Psi),
	}
}

func getIOStatsDiff(prev, curr *castaipb.IOStats) *castaipb.IOStats {
	if prev == nil || curr == nil {
		return &castaipb.IOStats{}
	}
	return &castaipb.IOStats{
		Psi: getPSIStatsDiff(prev.Psi, curr.Psi),
	}
}

func getPSIStatsDiff(prev, curr *castaipb.PSIStats) *castaipb.PSIStats {
	if prev == nil || curr == nil {
		return nil
	}
	res := &castaipb.PSIStats{}
	if curr.Some != nil && prev.Some != nil {
		res.Some = &castaipb.PSIData{
			Total: curr.Some.Total - prev.Some.Total,
		}
	}
	if curr.Full != nil && prev.Full != nil {
		res.Full = &castaipb.PSIData{
			Total: curr.Full.Total - prev.Full.Total,
		}
	}
	return res
}

func (c *Controller) collectStorageMetrics() {
	start := time.Now()
	c.log.Debug("starting storage metrics collection")

	c.initStorageState()

	timestamp := time.Now()
	if err := c.processBlockDeviceMetrics(timestamp); err != nil {
		c.log.Errorf("failed to collect block device metrics: %v", err)
	}

	if err := c.processFilesystemMetrics(timestamp); err != nil {
		c.log.Errorf("failed to collect filesystem metrics: %v", err)
	}

	c.log.Debugf("storage metrics collection completed in %v", time.Since(start))
}

func (c *Controller) initStorageState() {
	if c.storageState == nil {
		c.storageState = &storageMetricsState{
			blockDevices: make(map[string]*BlockDeviceMetrics),
			filesystems:  make(map[string]*FilesystemMetrics),
		}
	}
}

func (c *Controller) processBlockDeviceMetrics(timestamp time.Time) error {
	if c.blockDeviceMetrics == nil {
		return fmt.Errorf("block device metrics writer not initialized")
	}

	currentBlockMetrics, err := c.getBlockDeviceMetrics(c.nodeName, timestamp)
	if err != nil {
		return fmt.Errorf("failed to collect block device metrics: %w", err)
	}

	c.log.Debugf("collected %d raw block device metrics", len(currentBlockMetrics))

	for _, current := range currentBlockMetrics {
		if err := c.processBlockDeviceMetricWithRates(current); err != nil {
			c.log.Errorf("failed to process block device metric for %s: %v", current.Name, err)
			continue
		}
	}

	return nil
}

func (c *Controller) processBlockDeviceMetricWithRates(current BlockDeviceMetrics) error {
	prev, exists := c.storageState.blockDevices[current.Name]
	if exists {
		timeDiff := current.Timestamp.Sub(prev.Timestamp).Seconds()
		if timeDiff <= 0 {
			return fmt.Errorf("invalid time difference for device %s: %f seconds", current.Name, timeDiff)
		}

		c.calculateBlockDeviceRates(&current, prev, timeDiff)
		if err := c.blockDeviceMetrics.Write(current); err != nil {
			return fmt.Errorf("failed to write block device metric for %s: %w", current.Name, err)
		}
	}
	c.storageState.blockDevices[current.Name] = &current
	return nil
}

func (c *Controller) calculateBlockDeviceRates(current *BlockDeviceMetrics, prev *BlockDeviceMetrics, timeDiff float64) {
	current.ReadThroughput = (current.ReadThroughput - prev.ReadThroughput) / timeDiff
	current.WriteThroughput = (current.WriteThroughput - prev.WriteThroughput) / timeDiff
	current.ReadIOPS = int64(float64(current.ReadIOPS-prev.ReadIOPS) / timeDiff)
	current.WriteIOPS = int64(float64(current.WriteIOPS-prev.WriteIOPS) / timeDiff)
}

func (c *Controller) processFilesystemMetrics(timestamp time.Time) error {
	if c.filesystemMetrics == nil {
		return fmt.Errorf("filesystem metrics writer not initialized")
	}

	fsMetrics, err := c.getFilesystemMetrics(c.nodeName, timestamp)
	if err != nil {
		return fmt.Errorf("failed to collect filesystem metrics: %w", err)
	}

	c.log.Debugf("collected %d filesystem metrics", len(fsMetrics))

	for _, metric := range fsMetrics {
		if err := c.filesystemMetrics.Write(metric); err != nil {
			c.log.Errorf("failed to write filesystem metric for %s: %v", metric.MountPoint, err)
			continue
		}
	}

	return nil
}

func (c *Controller) getBlockDeviceMetrics(nodeName string, timestamp time.Time) ([]BlockDeviceMetrics, error) {
	ioStats, err := c.diskClient.IOCounters()
	if err != nil {
		return nil, fmt.Errorf("failed to get IO counters: %w", err)
	}

	blockMetrics := make([]BlockDeviceMetrics, 0, len(ioStats))

	for deviceName, stat := range ioStats {
		metric := c.buildBlockDeviceMetric(deviceName, stat, nodeName, timestamp)
		blockMetrics = append(blockMetrics, metric)
	}

	return blockMetrics, nil
}

func (c *Controller) buildBlockDeviceMetric(deviceName string, stat disk.IOCountersStat, nodeName string, timestamp time.Time) BlockDeviceMetrics {
	diskUsage, err := c.deviceInfoProvider.GetDeviceSize(deviceName)
	if err != nil {
		c.log.Warnf("failed to get disk usage for %s: %v", deviceName, err)
		diskUsage = 0
	}

	physicalDevices := c.resolvePhysicalDevices(deviceName)

	return BlockDeviceMetrics{
		Name:            deviceName,
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

func (c *Controller) getFilesystemMetrics(nodeName string, timestamp time.Time) ([]FilesystemMetrics, error) {
	partitions, err := c.diskClient.Partitions(false) // false = only physical devices
	if err != nil {
		return nil, fmt.Errorf("failed to get partitions: %w", err)
	}

	filesystemMetrics := make([]FilesystemMetrics, 0, len(partitions))
	for _, partition := range partitions {
		metric := c.buildFilesystemMetric(partition, nodeName, timestamp)
		filesystemMetrics = append(filesystemMetrics, metric)
	}

	c.log.Debugf("collected %d filesystem metrics", len(filesystemMetrics))
	return filesystemMetrics, nil
}

func (c *Controller) buildFilesystemMetric(partition disk.PartitionStat, nodeName string, timestamp time.Time) FilesystemMetrics {
	hostPath := hostRootPath + partition.Mountpoint
	usage := c.getFilesystemUsage(hostPath)
	devices := c.resolveDeviceHierarchy(partition.Device)

	return FilesystemMetrics{
		Devices:    devices,
		NodeName:   nodeName,
		MountPoint: partition.Mountpoint,
		TotalSize:  safeUint64ToInt64(usage.Total),
		UsedSpace:  safeUint64ToInt64(usage.Used),
		Timestamp:  timestamp,
	}
}

func (c *Controller) getFilesystemUsage(hostPath string) *disk.UsageStat {
	usage, err := c.diskClient.Usage(hostPath)
	if err != nil {
		c.log.Warnf("failed to get disk usage for %s: %v", hostPath, err)
		return &disk.UsageStat{}
	}
	return usage
}

func (c *Controller) resolveDeviceHierarchy(device string) []string {
	if slaves := c.resolveLVMSlaves(device); len(slaves) > 0 {
		return slaves
	}

	deviceName := strings.TrimPrefix(device, "/dev/")
	if slaves := c.resolveDeviceMapperSlaves(deviceName); len(slaves) > 0 {
		return slaves
	}

	return []string{device}
}

// resolveLVMSlaves resolves LVM logical volumes to their underlying physical devices.
// It handles the symlink chain: /dev/mapper/vg-lv → /dev/dm-X → /sys/block/dm-X/slaves/ → [sdf, sdg]
func (c *Controller) resolveLVMSlaves(device string) []string {
	if !strings.HasPrefix(device, "/dev/mapper/") {
		return nil
	}

	hostMapperPath := hostRootPath + device

	linkTarget, err := os.Readlink(hostMapperPath)
	if err != nil {
		c.log.Debugf("symlink resolution failed for %s: %v", device, err)
		return nil
	}

	resolvedPath := hostRootPath + "/dev/" + filepath.Base(linkTarget)

	const hostPrefix = hostRootPath + "/dev/"
	if !strings.HasPrefix(resolvedPath, hostPrefix) {
		c.log.Debugf("unexpected resolved path format: %s", resolvedPath)
		return nil
	}

	resolvedDeviceName := strings.TrimPrefix(resolvedPath, hostPrefix)
	slaves := c.resolveDeviceMapperSlaves(resolvedDeviceName)

	if len(slaves) > 0 {
		c.log.Debugf("found %d underlying devices for LVM %s: %v", len(slaves), device, slaves)
	}

	return slaves
}

func (c *Controller) resolveDeviceMapperSlaves(deviceName string) []string {
	slavesPath := fmt.Sprintf("/sys/block/%s/slaves", deviceName)

	exists, err := c.deviceInfoProvider.DeviceExists(slavesPath)
	if err != nil || !exists {
		return []string{}
	}

	slaves, err := c.deviceInfoProvider.GetDeviceSlaves(deviceName)
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

func (c *Controller) resolvePhysicalDevices(deviceName string) []string {
	visited := make(map[string]bool)
	physicalDevices := c.resolveToPhysicalDevices(deviceName, visited)

	if len(physicalDevices) == 0 {
		return []string{"/dev/" + deviceName}
	}

	return c.deduplicateDevices(physicalDevices)
}

func (c *Controller) resolveToPhysicalDevices(deviceName string, visited map[string]bool) []string {
	if visited[deviceName] {
		c.log.Warnf("circular dependency detected for device %s", deviceName)
		return []string{"/dev/" + deviceName}
	}
	visited[deviceName] = true

	slaves := c.readDeviceSlaves(deviceName)

	if len(slaves) == 0 {
		if parentDevice := c.findPartitionParent(deviceName); parentDevice != "" {
			return c.resolveToPhysicalDevices(parentDevice, visited)
		}
		return []string{"/dev/" + deviceName}
	}

	var allPhysicalDevices []string
	for _, slave := range slaves {
		slavePhysical := c.resolveToPhysicalDevices(slave, visited)
		allPhysicalDevices = append(allPhysicalDevices, slavePhysical...)
	}

	return allPhysicalDevices
}

// readDeviceSlaves reads the slave devices from /sys/block/DEVICE/slaves/
func (c *Controller) readDeviceSlaves(deviceName string) []string {
	slaves, err := c.deviceInfoProvider.GetDeviceSlaves(deviceName)
	if err != nil {
		c.log.Debugf("cannot read slaves for %s: %v", deviceName, err)
		return nil
	}

	for _, slaveName := range slaves {
		c.log.Debugf("found slave %s for device %s", slaveName, deviceName)
	}

	return slaves
}

func (c *Controller) findPartitionParent(deviceName string) string {
	parentDeviceName, err := c.deviceInfoProvider.FindPartitionParent(deviceName)
	if err != nil {
		c.log.Debugf("cannot find partition parent for %s: %v", deviceName, err)
		return ""
	}

	c.log.Debugf("found partition %s under parent %s", deviceName, parentDeviceName)
	return parentDeviceName
}

func (c *Controller) deduplicateDevices(devices []string) []string {
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
