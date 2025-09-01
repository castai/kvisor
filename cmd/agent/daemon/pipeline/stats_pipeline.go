package pipeline

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
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
		c.log.Debug("storage metrics not initialized, skipping")
		return
	}

	c.log.Debug("starting storage metrics collection")
	c.collectAndSendSystemStorageMetrics()
}

func (c *Controller) collectAndSendSystemStorageMetrics() {
	now := time.Now()

	if c.storageState == nil {
		c.storageState = &storageMetricsState{
			blockDevices: make(map[string]*BlockDeviceMetrics),
			filesystems:  make(map[string]*FilesystemMetrics),
		}
	}

	if c.blockDeviceMetrics != nil {
		currentBlockMetrics, err := collectBlockDeviceMetrics(c.nodeName, now)
		if err != nil {
			c.log.Errorf("failed to collect block device metrics: %v", err)
		} else {
			c.log.Infof("collected %d raw block device metrics", len(currentBlockMetrics))
			for _, current := range currentBlockMetrics {
				prev, exists := c.storageState.blockDevices[current.Name]
				if exists {
					timeDiff := current.Timestamp.Sub(prev.Timestamp).Seconds()
					c.log.Debugf("block device %s: time diff = %.2f seconds", current.Name, timeDiff)
					if timeDiff > 0 {
						current.ReadThroughput = (current.ReadThroughput - prev.ReadThroughput) / timeDiff
						current.WriteThroughput = (current.WriteThroughput - prev.WriteThroughput) / timeDiff

						current.ReadIOPS = int64(float64(current.ReadIOPS-prev.ReadIOPS) / timeDiff)
						current.WriteIOPS = int64(float64(current.WriteIOPS-prev.WriteIOPS) / timeDiff)

						c.log.Debugf("block device %s: calculated rates - ReadIOPS=%d, WriteIOPS=%d",
							current.Name, current.ReadIOPS, current.WriteIOPS)

						if err := c.blockDeviceMetrics.Write(current); err != nil {
							c.log.Errorf("failed to write block device metric for %s: %v", current.Name, err)
						}
					} else {
						c.log.Debugf("skipping block device %s: zero time difference", current.Name)
					}
				} else {
					c.log.Debugf("storing initial block device %s metrics (no previous data)", current.Name)
				}
				c.storageState.blockDevices[current.Name] = &current
			}
		}
	} else {
		c.log.Warn("block device metrics not initialized, skipping collection")
	}

	if c.filesystemMetrics != nil {
		fsMetrics, err := collectFilesystemMetrics(c.nodeName, now)
		if err != nil {
			c.log.Errorf("failed to collect filesystem metrics: %v", err)
		} else {
			c.log.Infof("collected %d filesystem metrics", len(fsMetrics))
			writtenCount := 0
			for _, metric := range fsMetrics {
				if err := c.filesystemMetrics.Write(metric); err != nil {
					c.log.Errorf("failed to write filesystem metric for %s: %v", metric.MountPoint, err)
				} else {
					writtenCount++
				}
			}
			c.log.Infof("successfully wrote %d filesystem metrics to storage", writtenCount)
		}
	} else {
		c.log.Warn("filesystem metrics not initialized, skipping collection")
	}
}

func collectBlockDeviceMetrics(nodeName string, timestamp time.Time) ([]BlockDeviceMetrics, error) {
	var metrics []BlockDeviceMetrics

	ioStats, err := disk.IOCounters()
	if err != nil {
		return nil, err
	}

	for deviceName, stat := range ioStats {

		metrics = append(metrics, BlockDeviceMetrics{
			Name:            deviceName,
			NodeName:        nodeName,
			ReadIOPS:        int64(stat.ReadCount),
			WriteIOPS:       int64(stat.WriteCount),
			ReadThroughput:  float64(stat.ReadBytes),
			WriteThroughput: float64(stat.WriteBytes),
			Size:            int64(calculateDiskSize(deviceName)),
			Timestamp:       timestamp,
		})
	}

	return metrics, nil
}

func collectFilesystemMetrics(nodeName string, timestamp time.Time) ([]FilesystemMetrics, error) {
	var metrics []FilesystemMetrics

	partitions, err := disk.Partitions(true) // false = physical devices only
	if err != nil {
		return nil, fmt.Errorf("failed to get partitions: %w", err)
	}

	slog.Info("collectFilesystemMetrics", "total_partitions", len(partitions), "node", nodeName)

	for i, partition := range partitions {
		slog.Debug("processing partition", 
			"index", i,
			"device", partition.Device, 
			"mountpoint", partition.Mountpoint, 
			"fstype", partition.Fstype,
			"opts", partition.Opts)

		usage, err := disk.Usage(partition.Mountpoint)
		if err != nil {
			slog.Warn("failed to get disk usage", 
				"mountpoint", partition.Mountpoint, 
				"device", partition.Device, 
				"error", err)
			continue
		}

		devices := getDevicesForPartition(partition)

		slog.Info("filesystem metric collected",
			"device", partition.Device,
			"mountpoint", partition.Mountpoint,
			"detected_devices", devices,
			"total_size", usage.Total,
			"multi_device", len(devices) > 1)

		metrics = append(metrics, FilesystemMetrics{
			Devices:        devices,
			NodeName:       nodeName,
			MountPoint:     partition.Mountpoint,
			TotalSize:      int64(usage.Total),
			UsedSpace:      int64(usage.Used),
			AvailableSpace: int64(usage.Free),
			Timestamp:      timestamp,
		})
	}

	slog.Info("collectFilesystemMetrics completed", 
		"total_metrics", len(metrics), 
		"node", nodeName)

	return metrics, nil
}

func calculateDiskSize(deviceName string) int64 {
	usage, err := disk.Usage(deviceName)
	if err != nil {
		return 0
	}
	return int64(usage.Total)
}

func getDevicesForPartition(partition disk.PartitionStat) []string {
	if partition.Device == "" {
		slog.Debug("empty device for partition", "mountpoint", partition.Mountpoint)
		return []string{"unknown"}
	}

	slog.Debug("detecting devices for partition", 
		"device", partition.Device, 
		"mountpoint", partition.Mountpoint,
		"fstype", partition.Fstype)

	// Try gopsutil + /sys/block approach for device hierarchy detection
	devices := getDeviceHierarchy(partition.Device)
	if len(devices) > 1 {
		slog.Info("multi-device detected", 
			"original_device", partition.Device,
			"underlying_devices", devices,
			"count", len(devices))
		return devices
	}

	slog.Debug("single device detected", 
		"device", partition.Device,
		"detected_devices", devices)

	// Return the detected devices (even if single)
	return devices
}

func getDeviceHierarchy(device string) []string {
	deviceName := strings.TrimPrefix(device, "/dev/")
	
	slog.Debug("getDeviceHierarchy", "device", device, "deviceName", deviceName)

	// 1. Check if it's a device mapper device using gopsutil
	if label, err := disk.Label(deviceName); err == nil && label != "" {
		slog.Debug("device mapper label found", "device", deviceName, "label", label)
		// This is a device mapper device, get underlying devices
		if slaves := getDeviceMapperSlaves(deviceName); len(slaves) > 0 {
			slog.Info("device mapper slaves found", "device", deviceName, "slaves", slaves)
			return slaves
		}
	} else if err != nil {
		slog.Debug("disk.Label failed", "device", deviceName, "error", err)
	}

	// 2. For /dev/mapper/ devices, resolve symlinks (like gopsutil does internally)
	if strings.HasPrefix(device, "/dev/mapper/") {
		slog.Debug("checking /dev/mapper/ device", "device", device)
		if devpath, err := filepath.EvalSymlinks(device); err == nil {
			slog.Debug("resolved symlink", "original", device, "resolved", devpath)
			// Extract device name and get slaves
			resolvedName := strings.TrimPrefix(devpath, "/dev/")
			if slaves := getDeviceMapperSlaves(resolvedName); len(slaves) > 0 {
				slog.Info("mapper symlink slaves found", "device", device, "resolved", resolvedName, "slaves", slaves)
				return slaves
			}
		} else {
			slog.Debug("symlink resolution failed", "device", device, "error", err)
		}
	}

	// 3. Check for RAID devices (md devices)
	if strings.HasPrefix(deviceName, "md") {
		slog.Debug("checking RAID device", "device", deviceName)
		if slaves := getDeviceMapperSlaves(deviceName); len(slaves) > 0 {
			slog.Info("RAID slaves found", "device", deviceName, "slaves", slaves)
			return slaves
		}
	}

	slog.Debug("no multi-device hierarchy found", "device", device, "fallback", []string{device})
	return []string{device}
}

func getDeviceMapperSlaves(deviceName string) []string {
	// Read /sys/block/{device}/slaves/ directory to find underlying devices
	slavesPath := fmt.Sprintf("/sys/block/%s/slaves", deviceName)
	
	slog.Debug("checking slaves directory", "device", deviceName, "path", slavesPath)

	entries, err := os.ReadDir(slavesPath)
	if err != nil {
		slog.Debug("no slaves directory found", "device", deviceName, "path", slavesPath, "error", err)
		// No slaves directory means it's likely a physical device
		return []string{}
	}

	var slaves []string
	for _, entry := range entries {
		if entry.IsDir() {
			slog.Debug("skipping directory in slaves", "device", deviceName, "entry", entry.Name())
			continue
		}
		slaveName := entry.Name()
		slaves = append(slaves, "/dev/"+slaveName)
		slog.Debug("found slave device", "parent", deviceName, "slave", slaveName)
	}

	if len(slaves) > 0 {
		slog.Info("slaves discovered", "device", deviceName, "slaves", slaves, "count", len(slaves))
	} else {
		slog.Debug("no slaves found", "device", deviceName)
	}

	return slaves
}
