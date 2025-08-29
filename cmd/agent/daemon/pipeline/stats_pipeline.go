package pipeline

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"time"

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
	ReadThroughput  float64   `avro:"read_throughput"`
	WriteThroughput float64   `avro:"write_throughput"`
	Timestamp       time.Time `avro:"ts"`
}

type FilesystemMetrics struct {
	Device         string    `avro:"device"`
	NodeName       string    `avro:"node_name"`
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

type blockDeviceState struct {
	name            string
	readBytesTotal  uint64
	writeBytesTotal uint64
	scrapedAt       time.Time

	prevReadBytesTotal  uint64
	prevWriteBytesTotal uint64
	prevScrapedAt       time.Time
}

type storageMetricsState struct {
	blockDevices map[string]*blockDeviceState
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
	if c.k8sClient == nil || c.blockDeviceMetrics == nil || c.filesystemMetrics == nil {
		c.log.Debug("storage metrics not initialized, skipping")
		return
	}
	req := c.k8sClient.CoreV1().RESTClient().Get().
		Resource("nodes").
		Name(c.nodeName).
		SubResource("proxy").
		Suffix("metrics/cadvisor")

	body, err := req.DoRaw(context.TODO())
	if err != nil {
		c.log.Errorf("failed to fetch cadvisor metrics via k8s client: %v", err)
		return
	}

	c.parseAndSendCadvisorMetrics(string(body))
}

func (c *Controller) parseAndSendCadvisorMetrics(metricsData string) {
	lines := strings.Split(metricsData, "\n")
	timestamp := time.Now()

	currentBlockDevices := make(map[string]*blockDeviceState)
	currentFilesystems := make(map[string]*FilesystemMetrics)

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.Contains(line, "container_fs_limit_bytes") ||
			strings.Contains(line, "container_fs_usage_bytes") {
			c.parseFilesystemMetric(line, timestamp, currentFilesystems)
		}

		if strings.Contains(line, "container_blkio_device_usage_total") {
			c.parseBlockDeviceCounters(line, timestamp, currentBlockDevices)
		}
	}

	for deviceName, currentState := range currentBlockDevices {
		prevState, exists := c.storageState.blockDevices[deviceName]
		if !exists {
			c.storageState.blockDevices[deviceName] = currentState
			continue
		}

		intervalSeconds := currentState.scrapedAt.Sub(prevState.scrapedAt).Seconds()
		if intervalSeconds <= 0 {
			c.log.Warnf("invalid interval for device %s: %v seconds", deviceName, intervalSeconds)
			continue
		}

		readBytesDiff := currentState.readBytesTotal - prevState.readBytesTotal
		writeBytesDiff := currentState.writeBytesTotal - prevState.writeBytesTotal

		blockMetric := &BlockDeviceMetrics{
			Name:            deviceName,
			NodeName:        c.nodeName,
			Timestamp:       timestamp,
			ReadThroughput:  float64(readBytesDiff) / intervalSeconds,
			WriteThroughput: float64(writeBytesDiff) / intervalSeconds,
		}

		if err := c.blockDeviceMetrics.Write(*blockMetric); err != nil {
			c.log.Errorf("failed to write block device metric: %v", err)
		}

		prevState.prevReadBytesTotal = prevState.readBytesTotal
		prevState.prevWriteBytesTotal = prevState.writeBytesTotal
		prevState.prevScrapedAt = prevState.scrapedAt

		prevState.readBytesTotal = currentState.readBytesTotal
		prevState.writeBytesTotal = currentState.writeBytesTotal
		prevState.scrapedAt = currentState.scrapedAt
	}

	for _, fs := range currentFilesystems {
		if fs.TotalSize > 0 && fs.UsedSpace >= 0 {
			fs.AvailableSpace = fs.TotalSize - fs.UsedSpace
		}

		if err := c.filesystemMetrics.Write(*fs); err != nil {
			c.log.Errorf("failed to write filesystem metric: %v", err)
		}
		c.storageState.filesystems[fs.Device] = fs
	}
}

func (c *Controller) parseFilesystemMetric(line string, timestamp time.Time, filesystems map[string]*FilesystemMetrics) {
	value, labels := c.parsePrometheusLine(line)
	if value == nil {
		return
	}

	device, hasDevice := labels["device"]
	if !hasDevice {
		return
	}

	key := device
	if filesystems[key] == nil {
		filesystems[key] = &FilesystemMetrics{
			NodeName:  c.nodeName,
			Device:    device,
			Timestamp: timestamp,
		}
	}

	fs := filesystems[key]
	if strings.Contains(line, "container_fs_limit_bytes") {
		fs.TotalSize = int64(*value)
	} else if strings.Contains(line, "container_fs_usage_bytes") {
		fs.UsedSpace = int64(*value)
	}
}

func (c *Controller) parseBlockDeviceCounters(line string, timestamp time.Time, blockDevices map[string]*blockDeviceState) {
	value, labels := c.parsePrometheusLine(line)
	if value == nil {
		return
	}

	device, hasDevice := labels["device"]
	if !hasDevice {
		return
	}

	operation, hasOperation := labels["operation"]
	if !hasOperation {
		return
	}

	if blockDevices[device] == nil {
		blockDevices[device] = &blockDeviceState{
			name:      device,
			scrapedAt: timestamp,
		}
	}

	bd := blockDevices[device]
	uintValue := uint64(*value)

	switch operation {
	case "Read":
		bd.readBytesTotal = uintValue
	case "Write":
		bd.writeBytesTotal = uintValue
	}
}

func (c *Controller) parsePrometheusLine(line string) (*float64, map[string]string) {
	// Split metric name/labels from value and timestamp
	// Format: metric_name{labels} value timestamp
	parts := strings.Fields(line)
	if len(parts) < 3 {
		return nil, nil
	}

	// Take the second-to-last part as the value (last part is timestamp)
	value, err := strconv.ParseFloat(parts[len(parts)-2], 64)
	if err != nil {
		return nil, nil
	}

	metricPart := parts[0]
	labels := make(map[string]string)

	start := strings.Index(metricPart, "{")
	end := strings.LastIndex(metricPart, "}")
	if start != -1 && end != -1 && start < end {
		labelStr := metricPart[start+1 : end]
		labelPairs := strings.Split(labelStr, ",")

		for _, pair := range labelPairs {
			kvParts := strings.SplitN(strings.TrimSpace(pair), "=", 2)
			if len(kvParts) == 2 {
				key := strings.TrimSpace(kvParts[0])
				val := strings.Trim(strings.TrimSpace(kvParts[1]), `"`)
				labels[key] = val
			}
		}
	}

	return &value, labels
}
