package state

import (
	"context"
	"log/slog"
	"time"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/metrics"
	"github.com/castai/kvisor/pkg/containers"
)

func (c *Controller) runContainerStatsPipeline(ctx context.Context) error {
	c.log.Info("running container stats pipeline")
	defer c.log.Info("container stats pipeline done")

	ticker := time.NewTicker(c.cfg.ContainerStatsScrapeInterval)
	defer ticker.Stop()

	// Initial scrape to populate metrics for diff.
	c.scrapeContainersResourceStats(nil)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			batch := &castpb.ContainerStatsBatch{}
			c.scrapeContainersResourceStats(batch)
			if len(batch.Items) > 0 {
				for _, exp := range c.exporters.ContainerStats {
					exp.Enqueue(batch)
				}
			}
		}
	}
}

func (c *Controller) scrapeContainersResourceStats(batch *castpb.ContainerStatsBatch) {
	for _, cont := range c.containersClient.ListContainers() {
		c.scrapeContainerResourcesStats(cont, batch)
	}
}

func (c *Controller) scrapeContainerResourcesStats(cont *containers.Container, batch *castpb.ContainerStatsBatch) {
	now := time.Now().UTC()
	cgStats, err := c.containersClient.GetCgroupStats(cont)
	if err != nil {
		if c.log.IsEnabled(slog.LevelDebug) {
			c.log.Errorf("getting cgroup stats for container %q: %v", cont.Name, err)
		}
		metrics.AgentContainerStatsScrapeErrorsTotal.Inc()
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

	item := &castpb.ContainerStats{
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
	batch.Items = append(batch.Items, item)

	if podInfo, ok := c.getPodInfo(cont.PodUID); ok {
		item.NodeName = podInfo.NodeName
		item.WorkloadName = podInfo.WorkloadName
		item.WorkloadKind = podInfo.WorkloadKind
	}

	prevScrape.ts = currScrape.ts
	prevScrape.cpuStat = currScrape.cpuStat
}

func getCPUStatsDiff(prev, curr *containerStatsScrapePoint) *castpb.CpuStats {
	return &castpb.CpuStats{
		TotalUsage:        curr.cpuStat.TotalUsage - prev.cpuStat.TotalUsage,
		UsageInKernelmode: curr.cpuStat.UsageInKernelmode - prev.cpuStat.UsageInKernelmode,
		UsageInUsermode:   curr.cpuStat.UsageInUsermode - prev.cpuStat.UsageInUsermode,
		ThrottledPeriods:  curr.cpuStat.ThrottledPeriods,
		ThrottledTime:     curr.cpuStat.ThrottledTime,
		Psi:               curr.cpuStat.Psi,
	}
}
