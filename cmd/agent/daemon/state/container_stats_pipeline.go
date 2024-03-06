package state

import (
	"context"
	"errors"
	"io"
	"math"
	"time"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/netstats"
	"github.com/castai/kvisor/pkg/containers"
	"github.com/castai/kvisor/pkg/ebpftracer"
	"github.com/castai/kvisor/pkg/metrics"
	"github.com/castai/kvisor/pkg/stats"
	"github.com/samber/lo"
	"google.golang.org/grpc/codes"
	"k8s.io/apimachinery/pkg/api/resource"
)

func (c *Controller) runContainerStatsPipeline(ctx context.Context) error {
	c.log.Info("running container stats sink loop")
	defer c.log.Info("container stats sink loop done")

	var writeStream castpb.RuntimeSecurityAgentAPI_ContainerStatsWriteStreamClient
	var err error
	defer func() {
		if writeStream != nil {
			_ = writeStream.CloseSend()
		}
	}()

	send := func(batch *castpb.ContainerStatsBatch) {
		c.log.Debugf("sending container cgroup stats, items=%d", len(batch.GetItems()))
		if err := writeStream.Send(batch); err != nil {
			if errors.Is(err, io.EOF) {
				writeStream = nil
			}
			c.log.Errorf("sending container cgroup stats: %v", err)
			return
		}
		metrics.AgentExportedContainerStatsTotal.Inc()
	}

	ticker := time.NewTicker(c.cfg.ContainerStatsScrapeInterval)
	defer ticker.Stop()

	for {
		// Create stream.
		if writeStream == nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				writeStream, err = c.castClient.GRPC.ContainerStatsWriteStream(ctx)
				if err != nil {
					if !isGRPCError(err, codes.Unavailable, codes.Canceled) {
						c.log.Warnf("create write stream: %v", err)
					}
					time.Sleep(c.writeStreamCreateRetryDelay)
					continue
				}
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			batch := &castpb.ContainerStatsBatch{}
			c.scrapeContainersResourceStats(batch)
			c.scrapeContainersSyscallStats(ctx, batch)
			if len(batch.GetItems()) > 0 {
				send(batch)
			}
		}
	}
}

func (c *Controller) scrapeContainersResourceStats(batch *castpb.ContainerStatsBatch) {
	for _, cont := range c.containersClient.ListContainers() {
		if cont.Name == "" {
			// We ignore containers that do not have a name, as they are likely just the pause containers.
			continue
		}

		if len(cont.PIDs) == 0 {
			continue
		}

		now := time.Now().UTC()
		cpu, err := cont.Cgroup.CpuStat()
		if err != nil {
			// TODO: Metrics
			continue
		}
		mem, err := cont.Cgroup.MemoryStat()
		if err != nil {
			// TODO: Metrics
			continue
		}

		netStats, err := c.netStatsReader.Read(cont.PIDs[0])
		if err != nil {
			// TODO: metrics or handle this better, getting sometimes no such file or directory
			continue
		}
		mainNicStats, _ := lo.Find(netStats, func(item netstats.InterfaceStats) bool {
			return item.Name == "eth0"
		})

		currScrape := &resourcesStatsScrapePoint{
			ts:       now,
			cpuStat:  cpu,
			memStats: mem,
			netStats: &mainNicStats,
		}

		// We need at least 2 scrapes to calculate diff count.
		c.resourcesStatsScrapePointsMu.RLock()
		prevScrape, found := c.resourcesStatsScrapePoints[cont.CgroupID]
		c.resourcesStatsScrapePointsMu.RUnlock()
		if !found {
			c.resourcesStatsScrapePointsMu.Lock()
			c.resourcesStatsScrapePoints[cont.CgroupID] = currScrape
			c.resourcesStatsScrapePointsMu.Unlock()
			continue
		}

		pbStats := c.collectContainerResourcesStats(prevScrape, currScrape)
		batch.Items = append(batch.GetItems(), &castpb.ContainerStats{
			Namespace:     cont.PodNamespace,
			PodName:       cont.PodName,
			ContainerName: cont.Name,
			PodUid:        cont.PodUID,
			ContainerId:   cont.ID,
			Stats:         pbStats,
		})

		prevScrape.ts = currScrape.ts
		prevScrape.cpuStat = currScrape.cpuStat
		prevScrape.memStats = currScrape.memStats
		prevScrape.netStats = currScrape.netStats
	}
}

func (c *Controller) collectContainerResourcesStats(prev, curr *resourcesStatsScrapePoint) []*castpb.Stats {
	// TODO(Kvisord): Add io stats.
	var pbStats []*castpb.Stats

	// CPU stats. Stored as cpu millicores used during this scrape period.
	// Stored values can be used directly with `avg(value)`.
	window := curr.ts.Sub(prev.ts)
	cpuUsage := uint64Quantity(uint64((curr.cpuStat.UsageSeconds-prev.cpuStat.UsageSeconds)/window.Seconds()*1e9), resource.DecimalSI, -9)
	cpuThrottled := uint64Quantity(uint64((curr.cpuStat.ThrottledTimeSeconds-prev.cpuStat.ThrottledTimeSeconds)/window.Seconds()*1e9), resource.DecimalSI, -9)
	if v := cpuUsage.MilliValue(); v > 0 {
		pbStats = append(pbStats, &castpb.Stats{
			Group:    castpb.StatsGroup_STATS_GROUP_CPU,
			Subgroup: stats.SubgroupCPUUsage,
			Value:    float64(v),
		})
	}
	if v := cpuThrottled.MilliValue(); v > 0 {
		pbStats = append(pbStats, &castpb.Stats{
			Group:    castpb.StatsGroup_STATS_GROUP_CPU,
			Subgroup: stats.SubgroupCPUThrottled,
			Value:    float64(v),
		})
	}

	// Memory stats.
	if v := curr.memStats.RSS; v > 0 {
		pbStats = append(pbStats, &castpb.Stats{
			Group:    castpb.StatsGroup_STATS_GROUP_MEMORY,
			Subgroup: stats.SubgroupMemoryUsage,
			Value:    float64(v),
		})
	}
	if v := curr.memStats.Limit; v > 0 {
		pbStats = append(pbStats, &castpb.Stats{
			Group:    castpb.StatsGroup_STATS_GROUP_MEMORY,
			Subgroup: stats.SubgroupMemoryLimit,
			Value:    float64(v),
		})
	}

	// Network stats. Saved as deltas.
	// Stored values can be converted to rate similar to prometheus by `sum(value)/60` for period is one minute.
	if v := curr.netStats.TxBytes - prev.netStats.TxBytes; v > 0 {
		pbStats = append(pbStats, &castpb.Stats{
			Group:    castpb.StatsGroup_STATS_GROUP_NET,
			Subgroup: stats.SubgroupNetworkTxBytes,
			Value:    float64(v),
		})
	}
	if v := curr.netStats.TxDropped - prev.netStats.TxDropped; v > 0 {
		pbStats = append(pbStats, &castpb.Stats{
			Group:    castpb.StatsGroup_STATS_GROUP_NET,
			Subgroup: stats.SubgroupNetworkTxDropped,
			Value:    float64(v),
		})
	}
	if v := curr.netStats.RxBytes - prev.netStats.RxBytes; v > 0 {
		pbStats = append(pbStats, &castpb.Stats{
			Group:    castpb.StatsGroup_STATS_GROUP_NET,
			Subgroup: stats.SubgroupNetworkRxBytes,
			Value:    float64(v),
		})
	}
	if v := curr.netStats.RxDropped - prev.netStats.RxDropped; v > 0 {
		pbStats = append(pbStats, &castpb.Stats{
			Group:    castpb.StatsGroup_STATS_GROUP_NET,
			Subgroup: stats.SubgroupNetworkRxDropped,
			Value:    float64(v),
		})
	}

	return pbStats
}

func (c *Controller) scrapeContainersSyscallStats(ctx context.Context, batch *castpb.ContainerStatsBatch) {
	st, err := c.tracer.ReadSyscallStats()
	if err != nil {
		c.log.Errorf("reading syscalls stats from kernel: %v", err)
		return
	}

	for cgroupID, syscallStats := range st {
		cont, err := c.containersClient.GetContainerForCgroup(ctx, uint64(cgroupID))
		if err != nil {
			if !errors.Is(err, containers.ErrContainerNotFound) {
				c.log.Errorf("getting container: %v", err)
			}
			continue
		}

		// We need at least 2 scrapes to calculate diff count.
		c.syscallScrapePointsMu.RLock()
		prevScrape, found := c.syscallScrapePoints[cont.CgroupID]
		c.syscallScrapePointsMu.RUnlock()
		if !found {
			syscalls := make(map[ebpftracer.SyscallID]uint64, len(syscallStats))
			for _, v := range syscallStats {
				syscalls[v.ID] = v.Count
			}
			c.syscallScrapePointsMu.Lock()
			c.syscallScrapePoints[cont.CgroupID] = &syscallScrapePoint{
				syscalls: syscalls,
			}
			c.syscallScrapePointsMu.Unlock()
			continue
		}

		cgStats := &castpb.ContainerStats{
			Namespace:     cont.PodNamespace,
			PodName:       cont.PodName,
			ContainerName: cont.Name,
			PodUid:        cont.PodUID,
			ContainerId:   cont.ID,
		}
		for _, stat := range syscallStats {
			prevValue := prevScrape.syscalls[stat.ID]
			currValue := float64(stat.Count - prevValue)
			if currValue == 0 {
				continue
			}
			cgStats.Stats = append(cgStats.GetStats(), &castpb.Stats{
				Group:    castpb.StatsGroup_STATS_GROUP_SYSCALL,
				Subgroup: uint32(stat.ID),
				Value:    currValue,
			})
		}
		if len(cgStats.GetStats()) > 0 {
			batch.Items = append(batch.GetItems(), cgStats)
		}

		syscalls := make(map[ebpftracer.SyscallID]uint64, len(syscallStats))
		for _, v := range syscallStats {
			syscalls[v.ID] = v.Count
		}
		prevScrape.syscalls = syscalls
	}
}

func uint64Quantity(val uint64, format resource.Format, scale resource.Scale) resource.Quantity {
	q := *resource.NewScaledQuantity(int64(val), scale)
	if val > math.MaxInt64 {
		q = *resource.NewScaledQuantity(int64(val/10), resource.Scale(1)+scale)
	}
	q.Format = format
	return q
}
