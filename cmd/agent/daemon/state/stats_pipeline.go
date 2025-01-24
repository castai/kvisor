package state

import (
	"context"
	"errors"
	"log/slog"
	"time"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/metrics"
	"github.com/castai/kvisor/pkg/cgroup"
	"github.com/castai/kvisor/pkg/containers"
)

type containerStatsScrapePoint struct {
	cpuStat *castaipb.CpuStats
	memStat *castaipb.MemoryStats
	ioStat  *castaipb.IOStats
}

type nodeScrapePoint struct {
	cpuStat *castaipb.CpuStats
	memStat *castaipb.MemoryStats
	ioStat  *castaipb.IOStats
}

func (c *Controller) runStatsPipeline(ctx context.Context) error {
	c.log.Info("running stats pipeline")
	defer c.log.Info("stats pipeline done")

	ticker := time.NewTicker(c.cfg.StatsScrapeInterval)
	defer ticker.Stop()

	// Initial scrape to populate initial points for diffs.
	c.scrapeNodeStats(nil)
	c.scrapeContainersResourceStats(nil)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			func() {
				start := time.Now()
				batch := &castaipb.StatsBatch{}
				c.scrapeNodeStats(batch)
				c.scrapeContainersResourceStats(batch)
				if len(batch.Items) > 0 {
					for _, exp := range c.exporters.Stats {
						exp.Enqueue(batch)
					}
				}
				c.log.Debugf("stats exported, duration=%v", time.Since(start))
			}()
		}
	}
}

func (c *Controller) scrapeContainersResourceStats(batch *castaipb.StatsBatch) {
	conts := c.containersClient.ListContainers()
	c.log.Debugf("scraping resource stats from %d containers", len(conts))
	for _, cont := range conts {
		c.scrapeContainerResourcesStats(cont, batch)
	}
}

func (c *Controller) scrapeContainerResourcesStats(cont *containers.Container, batch *castaipb.StatsBatch) {
	cgStats, err := c.containersClient.GetCgroupStats(cont)
	if err != nil {
		if errors.Is(err, cgroup.ErrStatsNotFound) {
			return
		}
		if c.log.IsEnabled(slog.LevelDebug) {
			c.log.Errorf("getting cgroup stats for container %q: %v", cont.Name, err)
		}
		metrics.AgentStatsScrapeErrorsTotal.WithLabelValues("container").Inc()
		return
	}

	currScrape := &containerStatsScrapePoint{
		cpuStat: cgStats.CpuStats,
		memStat: cgStats.MemoryStats,
		ioStat:  cgStats.IOStats,
	}

	// We need at least 2 scrapes to calculate diffs.
	// Diffs are needed for always increasing counters only because we store them as deltas.
	// This includes cpu usage and psi total value.
	c.containerStatsScrapePointsMu.RLock()
	prevScrape, found := c.containerStatsScrapePoints[cont.CgroupID]
	c.containerStatsScrapePointsMu.RUnlock()
	if !found {
		c.containerStatsScrapePointsMu.Lock()
		c.containerStatsScrapePoints[cont.CgroupID] = currScrape
		c.containerStatsScrapePointsMu.Unlock()
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
		CpuStats:      getCPUStatsDiff(prevScrape.cpuStat, currScrape.cpuStat),
		MemoryStats:   getMemoryStatsDiff(prevScrape.memStat, currScrape.memStat),
		PidsStats:     cgStats.PidsStats,
		IoStats:       getIOStatsDiff(prevScrape.ioStat, currScrape.ioStat),
	}
	if podInfo, ok := c.getPodInfo(cont.PodUID); ok {
		item.NodeName = podInfo.NodeName
		item.WorkloadName = podInfo.WorkloadName
		item.WorkloadKind = podInfo.WorkloadKind
	}
	batch.Items = append(batch.Items, &castaipb.StatsItem{Data: &castaipb.StatsItem_Container{Container: item}})

	prevScrape.cpuStat = currScrape.cpuStat
	prevScrape.memStat = currScrape.memStat
	prevScrape.ioStat = currScrape.ioStat
}

func (c *Controller) scrapeNodeStats(batch *castaipb.StatsBatch) {
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

		currScrape := &nodeScrapePoint{
			cpuStat: &castaipb.CpuStats{Psi: cpuPSI},
			memStat: &castaipb.MemoryStats{
				Usage:         memStats.Usage,
				SwapOnlyUsage: memStats.SwapOnlyUsage,
				Psi:           memoryPSI,
			},
			ioStat: &castaipb.IOStats{Psi: ioPSI},
		}

		// We need at least 2 scrapes to calculate diffs.
		// Diffs are needed for always increasing counters only because we store them as deltas.
		// This includes cpu usage and psi total value.
		if c.nodeScrapePoint == nil {
			c.nodeScrapePoint = currScrape
			return nil
		}
		if batch == nil {
			return nil
		}

		batch.Items = append(batch.Items, &castaipb.StatsItem{Data: &castaipb.StatsItem_Node{
			Node: &castaipb.NodeStats{
				NodeName:    c.nodeName,
				CpuStats:    getCPUStatsDiff(c.nodeScrapePoint.cpuStat, currScrape.cpuStat),
				MemoryStats: getMemoryStatsDiff(c.nodeScrapePoint.memStat, currScrape.memStat),
				IoStats:     getIOStatsDiff(c.nodeScrapePoint.ioStat, currScrape.ioStat),
			},
		}})

		c.nodeScrapePoint.cpuStat = currScrape.cpuStat
		c.nodeScrapePoint.memStat = currScrape.memStat
		c.nodeScrapePoint.ioStat = currScrape.ioStat

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
	return &castaipb.MemoryStats{
		Cache:         curr.Cache,
		Usage:         curr.Usage,
		SwapOnlyUsage: curr.SwapOnlyUsage,
		Psi:           getPSIStatsDiff(prev.Psi, curr.Psi),
	}
}

func getIOStatsDiff(prev, curr *castaipb.IOStats) *castaipb.IOStats {
	return &castaipb.IOStats{
		Psi: getPSIStatsDiff(prev.Psi, curr.Psi),
	}
}

func getPSIStatsDiff(prev, curr *castaipb.PSIStats) *castaipb.PSIStats {
	if prev == nil || curr == nil {
		return nil
	}
	return &castaipb.PSIStats{
		Some: &castaipb.PSIData{
			Total: curr.Some.Total - prev.Some.Total,
		},
		Full: &castaipb.PSIData{
			Total: curr.Full.Total - prev.Full.Total,
		},
	}
}
