package pipeline

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
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

type BlockDeviceMetrics struct {
	Name            string    `avro:"name"`
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
	if c.blockDeviceMetrics == nil || c.filesystemMetrics == nil {
		return
	}

	c.collectAndSendSystemStorageMetrics()
}

func (c *Controller) collectAndSendSystemStorageMetrics() {
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
	var metrics []BlockDeviceMetrics

	ioStats, err := disk.IOCounters()
	if err != nil {
		return nil, err
	}

	for deviceName, stat := range ioStats {
		c.log.Debugf("processing block device: %s", deviceName)
		diskUsage, err := calculateDiskSize(deviceName)
		if err != nil {
			c.log.Warnf("failed to get diskUsage for %s: %v", deviceName, err)
		}
		metrics = append(metrics, BlockDeviceMetrics{
			Name:            deviceName,
			NodeName:        nodeName,
			ReadIOPS:        int64(stat.ReadCount),
			WriteIOPS:       int64(stat.WriteCount),
			ReadThroughput:  float64(stat.ReadBytes),
			WriteThroughput: float64(stat.WriteBytes),
			Size:            diskUsage,
			Timestamp:       timestamp,
		})
	}

	return metrics, nil
}

func (c *Controller) collectFilesystemMetrics(nodeName string, timestamp time.Time) ([]FilesystemMetrics, error) {
	partitions, err := disk.Partitions(true) // true = physical and virtual devices
	if err != nil {
		return nil, fmt.Errorf("failed to get partitions: %w", err)
	}

	var metrics []FilesystemMetrics
	for _, partition := range partitions {
		metric, err := c.createFilesystemMetric(partition, nodeName, timestamp)
		if err != nil {
			hostPath := "/mnt/host" + partition.Mountpoint
			c.log.Warnf("failed to get disk usage",
				"mountpoint", partition.Mountpoint,
				"host_path", hostPath,
				"device", partition.Device,
				"error", err)
			continue
		}
		metrics = append(metrics, metric)
	}

	c.log.Infof("collectFilesystemMetrics completed", "total_metrics", len(metrics))
	return metrics, nil
}

func (c *Controller) createFilesystemMetric(partition disk.PartitionStat, nodeName string, timestamp time.Time) (FilesystemMetrics, error) {
	hostPath := "/mnt/host" + partition.Mountpoint
	usage, err := disk.Usage(hostPath)
	if err != nil {
		return FilesystemMetrics{}, err
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

func calculateDiskSize(deviceName string) (int64, error) {
	// disk.Usage() is designed for filesystems, not raw block devices
	// For block device metrics, we should get the actual device size, not filesystem size
	size := getBlockDeviceSize(deviceName)
	if size > 0 {
		return size, nil
	}
	
	// Fallback: try disk.Usage() with host path (mainly for debugging)
	hostDevicePath := "/mnt/host/dev/" + deviceName
	usage, err := disk.Usage(hostDevicePath)
	if err == nil {
		// This gives filesystem size, not device size - usually not what we want for block metrics
		return int64(usage.Total), nil
	}
	
	return 0, fmt.Errorf("failed to get size for device %s: both /sys/block and disk.Usage failed", deviceName)
}

var partitionRegex = regexp.MustCompile(`^(sd[a-z]+|nvme\d+n\d+|xvd[a-z]+)(\d+)$`)

func getBlockDeviceSize(deviceName string) int64 {
	if strings.Contains(deviceName, "/") {
		return 0 // Skip device names with slashes
	}

	// Try main device path first: /sys/block/<device>/size
	sizePath := fmt.Sprintf("/mnt/host/sys/block/%s/size", deviceName)
	data, err := os.ReadFile(sizePath)
	
	if err != nil {
		// Check if it's a partition (e.g., sda1, nvme0n1p1)
		if matches := partitionRegex.FindStringSubmatch(deviceName); matches != nil {
			baseDevice := matches[1]
			// Try partition path: /sys/block/<base_device>/<partition>/size
			partitionPath := fmt.Sprintf("/mnt/host/sys/block/%s/%s/size", baseDevice, deviceName)
			data, err = os.ReadFile(partitionPath)
			if err != nil {
				return 0
			}
			sizePath = partitionPath // Update for logging
		} else {
			return 0
		}
	}

	sizeStr := strings.TrimSpace(string(data))
	sectors, err := strconv.ParseInt(sizeStr, 10, 64)
	if err != nil {
		return 0
	}

	// Convert from 512-byte sectors to bytes
	return sectors * 512
}

func (c *Controller) getDeviceHierarchy(device string) []string {
	c.log.Debugf("getDeviceHierarchy: processing device %s", device)

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

	hostMapperPath := "/mnt/host" + device
	c.log.Debugf("resolving LVM device %s at %s", device, hostMapperPath)

	resolvedPath, err := filepath.EvalSymlinks(hostMapperPath)
	if err != nil {
		c.log.Debugf("symlink resolution failed for %s: %v", device, err)
		return nil
	}

	c.log.Debugf("resolved %s to %s", device, resolvedPath)

	const hostPrefix = "/mnt/host/dev/"
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
	slavesPath := fmt.Sprintf("/mnt/host/sys/block/%s/slaves", deviceName)
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
