package state

import (
	"context"
	"log/slog"
	"time"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/metrics"
	"github.com/castai/kvisor/pkg/containers"
)

func (c *Controller) runStatsPipeline(ctx context.Context) error {
	c.log.Info("running stats pipeline")
	defer c.log.Info("stats pipeline done")

	ticker := time.NewTicker(c.cfg.StatsScrapeInterval)
	defer ticker.Stop()

	// Initial scrape to populate container metrics for cpu diff.
	c.scrapeContainersResourceStats(nil)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			batch := &castaipb.StatsBatch{}
			c.scrapeNodeStats(batch)
			c.scrapeContainersResourceStats(batch)
			if len(batch.Items) > 0 {
				for _, exp := range c.exporters.Stats {
					exp.Enqueue(batch)
				}
			}
		}
	}
}

func (c *Controller) scrapeContainersResourceStats(batch *castaipb.StatsBatch) {
	for _, cont := range c.containersClient.ListContainers() {
		c.scrapeContainerResourcesStats(cont, batch)
	}
}

func (c *Controller) scrapeContainerResourcesStats(cont *containers.Container, batch *castaipb.StatsBatch) {
	now := time.Now().UTC()
	cgStats, err := c.containersClient.GetCgroupStats(cont)
	if err != nil {
		if c.log.IsEnabled(slog.LevelDebug) {
			c.log.Errorf("getting cgroup stats for container %q: %v", cont.Name, err)
		}
		metrics.AgentStatsScrapeErrorsTotal.WithLabelValues("container").Inc()
		return
	}

	currScrape := &containerStatsScrapePoint{
		ts:      now,
		cpuStat: cgStats.CpuStats,
	}

	// We need at least 2 scrapes to calculate cpu diff count.
	c.resourcesStatsScrapePointsMu.RLock()
	prevScrape, found := c.resourcesStatsScrapePoints[cont.CgroupID]
	c.resourcesStatsScrapePointsMu.RUnlock()
	if !found {
		c.resourcesStatsScrapePointsMu.Lock()
		c.resourcesStatsScrapePoints[cont.CgroupID] = currScrape
		c.resourcesStatsScrapePointsMu.Unlock()
		return
	}

	if batch == nil {
		return
	}

	item := &castaipb.ContainerStats{
		Namespace:     cont.PodNamespace,
		PodName:       cont.PodName,
		ContainerName: cont.Name,
		PodUid:        cont.PodUID,
		ContainerId:   cont.ID,
		CpuStats:      getCPUStatsDiff(prevScrape, currScrape),
		MemoryStats:   cgStats.MemoryStats,
		PidsStats:     cgStats.PidsStats,
		IoStats:       cgStats.IOStats,
	}
	if podInfo, ok := c.getPodInfo(cont.PodUID); ok {
		item.NodeName = podInfo.NodeName
		item.WorkloadName = podInfo.WorkloadName
		item.WorkloadKind = podInfo.WorkloadKind
	}
	batch.Items = append(batch.Items, &castaipb.StatsItem{Data: &castaipb.StatsItem_Container{Container: item}})

	prevScrape.ts = currScrape.ts
	prevScrape.cpuStat = currScrape.cpuStat
}

func (c *Controller) scrapeNodeStats(batch *castaipb.StatsBatch) {
	item := &castaipb.NodeStats{}
	if err := func() error {
		if c.procHandler.PSIEnabled() {
			cpuPSI, err := c.procHandler.GetPSIStats("cpu")
			if err != nil {
				return err
			}
			item.CpuStats = &castaipb.CpuStats{Psi: cpuPSI}

			memStats, err := c.procHandler.GetMeminfoStats()
			if err != nil {
				return err
			}
			item.MemoryStats = memStats
			memoryPSI, err := c.procHandler.GetPSIStats("memory")
			if err != nil {
				return err
			}
			item.MemoryStats.Psi = memoryPSI

			ioPSI, err := c.procHandler.GetPSIStats("io")
			if err != nil {
				return err
			}
			item.IoStats = &castaipb.IOStats{Psi: ioPSI}
			batch.Items = append(batch.Items, &castaipb.StatsItem{Data: &castaipb.StatsItem_Node{Node: item}})
		}
		return nil
	}(); err != nil {
		if c.log.IsEnabled(slog.LevelDebug) {
			c.log.Errorf("getting cgroup stats for node %q: %v", c.nodeName, err)
		}
		metrics.AgentStatsScrapeErrorsTotal.WithLabelValues("node").Inc()
		return
	}
}

func getCPUStatsDiff(prev, curr *containerStatsScrapePoint) *castaipb.CpuStats {
	return &castaipb.CpuStats{
		TotalUsage:        curr.cpuStat.TotalUsage - prev.cpuStat.TotalUsage,
		UsageInKernelmode: curr.cpuStat.UsageInKernelmode - prev.cpuStat.UsageInKernelmode,
		UsageInUsermode:   curr.cpuStat.UsageInUsermode - prev.cpuStat.UsageInUsermode,
		ThrottledPeriods:  curr.cpuStat.ThrottledPeriods,
		ThrottledTime:     curr.cpuStat.ThrottledTime,
		Psi:               curr.cpuStat.Psi,
	}
}
