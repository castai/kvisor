package pipeline

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
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

type DiskStatsProvider interface {
	IOCounters() (map[string]disk.IOCountersStat, error)
	Partitions(all bool) ([]disk.PartitionStat, error)
	Usage(path string) (*disk.UsageStat, error)
}

type RealDiskStatsProvider struct {
	hostPath string
}

func NewRealDiskStatsProvider() *RealDiskStatsProvider {
	return &RealDiskStatsProvider{hostPath: "/proc/1/root"}
}

func NewTestDiskStatsProvider(hostPath string) *RealDiskStatsProvider {
	return &RealDiskStatsProvider{hostPath: hostPath}
}

func (r *RealDiskStatsProvider) IOCounters() (map[string]disk.IOCountersStat, error) {
	return disk.IOCounters()
}

func (r *RealDiskStatsProvider) Partitions(all bool) ([]disk.PartitionStat, error) {
	return disk.Partitions(all)
}

func (r *RealDiskStatsProvider) Usage(path string) (*disk.UsageStat, error) {
	return disk.Usage(r.hostPath + path)
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
	Devices        []string  `avro:"devices"`
	NodeName       string    `avro:"node_name"`
	MountPoint     string    `avro:"mount_point"`
	TotalSize      int64     `avro:"total_size"`
	UsedSpace      int64     `avro:"used_space"`
	AvailableSpace int64     `avro:"available_space"`
	Timestamp      time.Time `avro:"ts"`
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
				c.scrapeStorageMetrics()
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

func (c *Controller) scrapeStorageMetrics() {
	now := time.Now()
	c.initStorageState()
	c.collectAndSendBlockDeviceMetrics(now)
	c.collectAndSendFilesystemMetrics(now)
}

func (c *Controller) initStorageState() {
	if c.storageState == nil {
		c.storageState = &storageMetricsState{
			blockDevices: make(map[string]*BlockDeviceMetrics),
			filesystems:  make(map[string]*FilesystemMetrics),
		}
	}
}

func (c *Controller) collectAndSendBlockDeviceMetrics(timestamp time.Time) {
	if c.blockDeviceMetrics == nil {
		return
	}

	currentBlockMetrics, err := c.collectBlockDeviceMetrics(c.nodeName, timestamp)
	if err != nil {
		c.log.Errorf("failed to collect block device metrics: %v", err)
		return
	}

	c.log.Infof("collected %d raw block device metrics", len(currentBlockMetrics))
	for _, current := range currentBlockMetrics {
		c.processAndSendBlockDeviceMetric(current)
	}
}

func (c *Controller) processAndSendBlockDeviceMetric(current BlockDeviceMetrics) {
	prev, exists := c.storageState.blockDevices[current.Name]
	if exists {
		timeDiff := current.Timestamp.Sub(prev.Timestamp).Seconds()
		if timeDiff > 0 {
			c.calculateBlockDeviceRates(&current, prev, timeDiff)
			if err := c.blockDeviceMetrics.Write(current); err != nil {
				c.log.Errorf("failed to write block device metric for %s: %v", current.Name, err)
			}
		}
	}
	c.storageState.blockDevices[current.Name] = &current
}

func (c *Controller) calculateBlockDeviceRates(current *BlockDeviceMetrics, prev *BlockDeviceMetrics, timeDiff float64) {
	current.ReadThroughput = (current.ReadThroughput - prev.ReadThroughput) / timeDiff
	current.WriteThroughput = (current.WriteThroughput - prev.WriteThroughput) / timeDiff
	current.ReadIOPS = int64(float64(current.ReadIOPS-prev.ReadIOPS) / timeDiff)
	current.WriteIOPS = int64(float64(current.WriteIOPS-prev.WriteIOPS) / timeDiff)
}

func (c *Controller) collectAndSendFilesystemMetrics(timestamp time.Time) {
	if c.filesystemMetrics == nil {
		return
	}

	fsMetrics, err := c.collectFilesystemMetrics(c.nodeName, timestamp)
	if err != nil {
		c.log.Errorf("failed to collect filesystem metrics: %v", err)
		return
	}

	c.log.Infof("collected %d filesystem metrics", len(fsMetrics))
	for _, metric := range fsMetrics {
		if err := c.filesystemMetrics.Write(metric); err != nil {
			c.log.Errorf("failed to write filesystem metric for %s: %v", metric.MountPoint, err)
		}
	}
}

func (c *Controller) collectBlockDeviceMetrics(nodeName string, timestamp time.Time) ([]BlockDeviceMetrics, error) {
	var blockMetrics []BlockDeviceMetrics

	ioStats, err := c.diskStatsProvider.IOCounters()
	if err != nil {
		return nil, err
	}

	for deviceName, stat := range ioStats {
		diskUsage, err := c.calculateDiskSize(deviceName)
		if err != nil {
			c.log.Warnf("failed to get disk usage for %s: %v", deviceName, err)
		}

		// Resolve physical devices for this block device
		physicalDevices := c.getBlockDevicePhysicalDevices(deviceName)

		blockMetrics = append(blockMetrics, BlockDeviceMetrics{
			Name:            deviceName,
			PhysicalDevices: physicalDevices,
			NodeName:        nodeName,
			ReadIOPS:        int64(stat.ReadCount),
			WriteIOPS:       int64(stat.WriteCount),
			ReadThroughput:  float64(stat.ReadBytes),
			WriteThroughput: float64(stat.WriteBytes),
			Size:            diskUsage,
			Timestamp:       timestamp,
		})
	}
	c.log.Infof("collection of block metrics completed completed. total_metrics: %d", len(blockMetrics))

	return blockMetrics, nil
}

func (c *Controller) collectFilesystemMetrics(nodeName string, timestamp time.Time) ([]FilesystemMetrics, error) {
	partitions, err := c.diskStatsProvider.Partitions(false) // true = physical and virtual devices
	if err != nil {
		return nil, fmt.Errorf("failed to get partitions: %w", err)
	}

	var filesystemMetrics []FilesystemMetrics
	for _, partition := range partitions {
		metric, err := c.createFilesystemMetric(partition, nodeName, timestamp)
		if err != nil {
			continue
		}
		filesystemMetrics = append(filesystemMetrics, metric)
	}

	c.log.Infof("collection of filesystem metrics completed completed. total_metrics: %d", len(filesystemMetrics))
	return filesystemMetrics, nil
}

func (c *Controller) createFilesystemMetric(partition disk.PartitionStat, nodeName string, timestamp time.Time) (FilesystemMetrics, error) {
	c.log.Debugf("attempting to get usage for: original=%s", partition.Mountpoint)
	
	usage, err := c.diskStatsProvider.Usage(partition.Mountpoint)
	if err != nil {
		usage = &disk.UsageStat{}
		c.log.Warnf("failed to get disk usage: mountpoint: %s, device: %s, error: %v", 
			partition.Mountpoint, partition.Device, err)
	} else {
		c.log.Debugf("successfully got usage: mountpoint=%s, total=%d, used=%d, free=%d", 
			partition.Mountpoint, usage.Total, usage.Used, usage.Free)
	}

	return FilesystemMetrics{
		Devices:        c.getDeviceHierarchy(partition.Device),
		NodeName:       nodeName,
		MountPoint:     partition.Mountpoint,
		TotalSize:      int64(usage.Total),
		UsedSpace:      int64(usage.Used),
		AvailableSpace: int64(usage.Free),
		Timestamp:      timestamp,
	}, nil
}

func (c *Controller) calculateDiskSize(deviceName string) (int64, error) {
	size := c.getBlockDeviceSize(deviceName)
	if size > 0 {
		return size, nil
	}

	return 0, fmt.Errorf("failed to get size for device %s", deviceName)
}

func (c *Controller) getBlockDeviceSize(deviceName string) int64 {
	basePath := "/sys/block"
	if c.testSysBlockPath != "" {
		basePath = c.testSysBlockPath + "/sys/block"
	}
	
	// Try whole device first: /sys/block/{device}/size
	if sectors := readSectorCount(fmt.Sprintf("%s/%s/size", basePath, deviceName)); sectors > 0 {
		return sectors * 512
	}

	// If that failed, try partition path: /sys/block/{parent}/{device}/size
	if sectors := c.findPartitionSize(deviceName, basePath); sectors > 0 {
		return sectors * 512
	}

	return 0
}

func (c *Controller) findPartitionSize(deviceName string, blockDir string) int64 {
	entries, err := os.ReadDir(blockDir)
	if err != nil {
		fmt.Printf("DEBUG: findPartitionSize cannot read %s: %v\n", blockDir, err)
		return 0
	}

	fmt.Printf("DEBUG: findPartitionSize searching for %s, found %d entries in %s\n", deviceName, len(entries), blockDir)
	
	for _, entry := range entries {
		// Check if entry is a directory or symlink pointing to a directory
		entryPath := fmt.Sprintf("%s/%s", blockDir, entry.Name())
		stat, err := os.Stat(entryPath) // os.Stat follows symlinks
		if err != nil || !stat.IsDir() {
			continue
		}

		// Try: /sys/block/{baseDevice}/{deviceName}/size
		partitionPath := fmt.Sprintf("%s/%s/%s/size", blockDir, entry.Name(), deviceName)
		fmt.Printf("DEBUG: trying partition path: %s\n", partitionPath)
		
		if sectors := readSectorCount(partitionPath); sectors > 0 {
			fmt.Printf("DEBUG: found partition %s with %d sectors\n", deviceName, sectors)
			return sectors
		}
	}

	fmt.Printf("DEBUG: partition %s not found in any parent device\n", deviceName)
	return 0
}

func readSectorCount(path string) int64 {
	data, err := os.ReadFile(path)
	if err != nil {
		// Debug log for file read errors
		fmt.Printf("DEBUG: failed to read %s: %v\n", path, err)
		return 0
	}

	sizeStr := strings.TrimSpace(string(data))
	sectors, err := strconv.ParseInt(sizeStr, 10, 64)
	if err != nil {
		// Debug log for parsing errors
		fmt.Printf("DEBUG: failed to parse sectors from %s, content='%s': %v\n", path, sizeStr, err)
		return 0
	}

	fmt.Printf("DEBUG: successfully read %s: %d sectors\n", path, sectors)
	return sectors
}

func (c *Controller) getDeviceHierarchy(device string) []string {
	// check for LVM devices via symlink resolution
	if slaves := c.resolveLVMDeviceSlaves(device); len(slaves) > 0 {
		return slaves
	}

	// check for RAID devices (md devices)
	deviceName := strings.TrimPrefix(device, "/dev/")
	if strings.HasPrefix(deviceName, "md") {
		if slaves := c.getDeviceMapperSlaves(deviceName); len(slaves) > 0 {
			return slaves
		}
	}

	c.log.Debugf("getDeviceHierarchy: no slaves found, returning single device %s", device)
	return []string{device}
}

// resolveLVMDeviceSlaves resolves LVM logical volumes to their underlying physical devices.
// It handles the symlink chain: /dev/mapper/vg-lv → /dev/dm-X → /sys/block/dm-X/slaves/ → [sdf, sdg]
// Returns the list of underlying physical devices or nil if not an LVM device.
func (c *Controller) resolveLVMDeviceSlaves(device string) []string {
	if !strings.HasPrefix(device, "/dev/mapper/") {
		return nil
	}

	hostMapperPath := device
	c.log.Debugf("resolving LVM device %s at %s", device, hostMapperPath)

	resolvedPath, err := filepath.EvalSymlinks(hostMapperPath)
	if err != nil {
		c.log.Debugf("symlink resolution failed for %s: %v", device, err)
		return nil
	}

	c.log.Debugf("resolved %s to %s", device, resolvedPath)

	const hostPrefix = "/dev/"
	if !strings.HasPrefix(resolvedPath, hostPrefix) {
		c.log.Debugf("unexpected resolved path format: %s", resolvedPath)
		return nil
	}

	resolvedDeviceName := strings.TrimPrefix(resolvedPath, hostPrefix)
	slaves := c.getDeviceMapperSlaves(resolvedDeviceName)

	if len(slaves) > 0 {
		c.log.Debugf("found %d underlying devices for LVM %s: %v", len(slaves), device, slaves)
	}

	return slaves
}

func (c *Controller) getDeviceMapperSlaves(deviceName string) []string {
	basePath := "/sys/block"
	if c.testSysBlockPath != "" {
		basePath = c.testSysBlockPath + "/sys/block"
	}
	
	slavesPath := fmt.Sprintf("%s/%s/slaves", basePath, deviceName)
	c.log.Debugf("checking slaves directory for %s at %s", deviceName, slavesPath)
	entries, err := os.ReadDir(slavesPath)
	if err != nil {
		c.log.Debugf("no slaves directory found for %s: %v", deviceName, err)
		return []string{}
	}

	slaves := c.collectSlaveDevices(entries, deviceName)
	c.log.Debugf("%d slaves discovered for %s", len(slaves), deviceName)
	return slaves
}

func (c *Controller) collectSlaveDevices(entries []os.DirEntry, deviceName string) []string {
	var slaves []string
	for _, entry := range entries {
		if entry.IsDir() {
			c.log.Debugf("skipping directory in slaves for %s: %s", deviceName, entry.Name())
			continue
		}
		slaveName := entry.Name()
		slaves = append(slaves, "/dev/"+slaveName)
		c.log.Debugf("found slave device %s for parent %s", slaveName, deviceName)
	}
	return slaves
}

// getBlockDevicePhysicalDevices resolves a block device to its underlying physical devices
func (c *Controller) getBlockDevicePhysicalDevices(deviceName string) []string {
	c.log.Debugf("resolving physical devices for block device: %s", deviceName)

	physicalDevices := c.resolveToPhysicalDevices(deviceName, make(map[string]bool))

	if len(physicalDevices) == 0 {
		c.log.Debugf("no physical devices found for %s, treating as physical", deviceName)
		return []string{"/dev/" + deviceName}
	}

	// Remove duplicates and sort for consistency
	uniqueDevices := c.removeDuplicateDevices(physicalDevices)
	c.log.Debugf("resolved %s to physical devices: %v", deviceName, uniqueDevices)
	return uniqueDevices
}

// resolveToPhysicalDevices recursively resolves a device to its physical dependencies
func (c *Controller) resolveToPhysicalDevices(deviceName string, visited map[string]bool) []string {
	// Prevent infinite loops
	if visited[deviceName] {
		c.log.Warnf("circular dependency detected for device %s", deviceName)
		return []string{"/dev/" + deviceName}
	}
	visited[deviceName] = true

	// Read slave devices from sysfs
	slaves := c.readDeviceSlaves(deviceName)

	if len(slaves) == 0 {
		// No slaves - this could be a physical device or a partition
		if parentDevice := c.getPartitionParentDevice(deviceName); parentDevice != "" {
			c.log.Debugf("device %s is a partition of %s", deviceName, parentDevice)
			// Recursively resolve the parent device
			return c.resolveToPhysicalDevices(parentDevice, visited)
		}

		// This is a physical device
		c.log.Debugf("device %s is a physical device", deviceName)
		return []string{"/dev/" + deviceName}
	}

	// This device has slaves - recursively resolve them
	var allPhysicalDevices []string
	for _, slave := range slaves {
		slavePhysical := c.resolveToPhysicalDevices(slave, visited)
		allPhysicalDevices = append(allPhysicalDevices, slavePhysical...)
	}

	return allPhysicalDevices
}

// readDeviceSlaves reads the slave devices from /sys/block/DEVICE/slaves/
func (c *Controller) readDeviceSlaves(deviceName string) []string {
	basePath := "/sys/block"
	if c.testSysBlockPath != "" {
		basePath = c.testSysBlockPath + "/sys/block"
	}
	
	slavesPath := fmt.Sprintf("%s/%s/slaves", basePath, deviceName)
	entries, err := os.ReadDir(slavesPath)
	if err != nil {
		c.log.Debugf("cannot read slaves for %s: %v", deviceName, err)
		return nil
	}

	var slaves []string
	for _, entry := range entries {
		if !entry.IsDir() {
			slaveName := entry.Name()
			slaves = append(slaves, slaveName)
			c.log.Debugf("found slave %s for device %s", slaveName, deviceName)
		}
	}

	return slaves
}

// getPartitionParentDevice checks if a device is a partition and returns its parent
func (c *Controller) getPartitionParentDevice(deviceName string) string {
	basePath := "/sys/block"
	if c.testSysBlockPath != "" {
		basePath = c.testSysBlockPath + "/sys/block"
	}
	
	// Look through /sys/block/ to find if deviceName appears as a subdirectory
	blockDevices, err := os.ReadDir(basePath)
	if err != nil {
		c.log.Debugf("cannot read %s: %v", basePath, err)
		return ""
	}

	for _, entry := range blockDevices {
		if !entry.IsDir() {
			continue
		}

		parentDeviceName := entry.Name()
		partitionPath := fmt.Sprintf("%s/%s/%s", basePath, parentDeviceName, deviceName)

		if _, err := os.Stat(partitionPath); err == nil {
			c.log.Debugf("found partition %s under parent %s", deviceName, parentDeviceName)
			return parentDeviceName
		}
	}

	return ""
}

// removeDuplicateDevices removes duplicate devices and sorts the result
func (c *Controller) removeDuplicateDevices(devices []string) []string {
	seen := make(map[string]bool)
	var unique []string

	for _, device := range devices {
		if !seen[device] {
			seen[device] = true
			unique = append(unique, device)
		}
	}

	// Sort for consistent output
	for i := 0; i < len(unique)-1; i++ {
		for j := i + 1; j < len(unique); j++ {
			if unique[i] > unique[j] {
				unique[i], unique[j] = unique[j], unique[i]
			}
		}
	}

	return unique
}
