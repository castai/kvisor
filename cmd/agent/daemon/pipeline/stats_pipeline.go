package pipeline

import (
	"context"
	"errors"
	"log/slog"
	"time"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/metrics"
	"github.com/castai/kvisor/pkg/cgroup"
	"github.com/castai/kvisor/pkg/containers"
	"google.golang.org/protobuf/proto"
)

type containerStatsGroup struct {
	pb      *castaipb.ContainerStats
	changed bool
}

type nodeScrapePoint struct {
	nodeName string
	cpuStat  *castaipb.CpuStats
	memStat  *castaipb.MemoryStats
	ioStat   *castaipb.IOStats
}

func (c *Controller) runStatsPipeline(ctx context.Context) error {
	c.log.Info("running stats pipeline")
	defer c.log.Info("stats pipeline done")

	ticker := time.NewTicker(c.cfg.Stats.ScrapeInterval)
	defer ticker.Stop()

	nodeStats := &nodeScrapePoint{
		nodeName: c.nodeName,
	}
	containerStatsGroups := map[uint64]*containerStatsGroup{}
	stats := newDataBatchStats()

	// Initial scrape to populate initial points for diffs.
	c.scrapeNodeStats(nodeStats, stats)
	c.scrapeContainersResourceStats(containerStatsGroups, stats)

	send := func() {
		items := make([]*castaipb.DataBatchItem, 0, stats.totalItems)
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
		c.sendDataBatch("container stats scrape", metrics.PipelineStats, items)
		stats.reset()
		for _, group := range containerStatsGroups {
			group.changed = false
		}
	}

	for {
		select {
		case cgroupID := <-c.deletedContainersContainerStatsQueue:
			delete(containerStatsGroups, cgroupID)
		default:
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			start := time.Now()
			c.scrapeNodeStats(nodeStats, stats)
			c.scrapeContainersResourceStats(containerStatsGroups, stats)
			send()
			c.log.Debugf("stats exported, duration=%v", time.Since(start))
		}
	}
}

func (c *Controller) scrapeContainersResourceStats(groups map[uint64]*containerStatsGroup, stats *dataBatchStats) {
	conts := c.containersClient.ListContainers(func(cont *containers.Container) bool {
		return cont.Err == nil && cont.Cgroup != nil && cont.Name != ""
	})
	c.log.Debugf("scraping resource stats from %d containers", len(conts))
	for _, cont := range conts {
		c.scrapeContainerResourcesStats(groups, cont, stats)
	}
}

func (c *Controller) scrapeContainerResourcesStats(groups map[uint64]*containerStatsGroup, cont *containers.Container, stats *dataBatchStats) {
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

	group, found := groups[cont.CgroupID]
	if !found {
		group = &containerStatsGroup{
			pb: &castaipb.ContainerStats{
				Namespace:     cont.PodNamespace,
				PodName:       cont.PodName,
				ContainerName: cont.Name,
				PodUid:        cont.PodUID,
				ContainerId:   cont.ID,
				CpuStats:      cgStats.CpuStats,
				MemoryStats:   cgStats.MemoryStats,
				PidsStats:     cgStats.PidsStats,
				IoStats:       cgStats.IOStats,
				NodeName:      c.nodeName,
			},
		}
		if podInfo, ok := c.getPodInfo(cont.PodUID); ok {
			group.pb.WorkloadName = podInfo.WorkloadName
			group.pb.WorkloadKind = workloadKindString(podInfo.WorkloadKind)
		}
		groups[cont.CgroupID] = group
		return
	}

	group.changed = true
	group.pb.CpuStats = getCPUStatsDiff(group.pb.CpuStats, cgStats.CpuStats)
	group.pb.MemoryStats = getMemoryStatsDiff(group.pb.MemoryStats, cgStats.MemoryStats)
	group.pb.IoStats = getIOStatsDiff(group.pb.IoStats, cgStats.IOStats)
	group.pb.PidsStats = cgStats.PidsStats
	stats.sizeBytes += proto.Size(group.pb)
	stats.totalItems++
}

func (c *Controller) scrapeNodeStats(nodeStats *nodeScrapePoint, stats *dataBatchStats) {
	if err := func() error {
		// For now, we only care about PSI related metrics on node.
		if !c.procHandler.PSIEnabled() {
			return nil
		}

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

		// We need at least 2 scrapes to calculate diffs.
		// Diffs are needed for always increasing counters only because we store them as deltas.
		// This includes cpu usage and psi total value.
		if nodeStats.cpuStat == nil {
			nodeStats.cpuStat = &castaipb.CpuStats{Psi: cpuPSI}
			nodeStats.memStat = &castaipb.MemoryStats{
				Usage:         memStats.Usage,
				SwapOnlyUsage: memStats.SwapOnlyUsage,
				Psi:           memoryPSI,
			}
			nodeStats.ioStat = &castaipb.IOStats{Psi: ioPSI}
			return nil
		}

		nodeStats.cpuStat = getCPUStatsDiff(nodeStats.cpuStat, &castaipb.CpuStats{Psi: cpuPSI})
		nodeStats.memStat = getMemoryStatsDiff(nodeStats.memStat, &castaipb.MemoryStats{
			Usage:         memStats.Usage,
			SwapOnlyUsage: memStats.SwapOnlyUsage,
			Psi:           memoryPSI,
		})
		nodeStats.ioStat = getIOStatsDiff(nodeStats.ioStat, &castaipb.IOStats{Psi: ioPSI})
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
