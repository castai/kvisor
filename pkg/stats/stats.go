package stats

import (
	"strconv"

	commonpb "github.com/castai/kvisor/api/v1/runtime"
)

const (
	SubgroupCPUUsage         = 1
	SubgroupCPUThrottled     = 2
	SubgroupMemoryUsage      = 11
	SubgroupMemoryLimit      = 12
	SubgroupNetworkTxBytes   = 21
	SubgroupNetworkRxBytes   = 22
	SubgroupNetworkTxDropped = 23
	SubgroupNetworkRxDropped = 24
)

func SubgroupString(subgroup int) string {
	switch subgroup {
	case SubgroupCPUUsage, SubgroupMemoryUsage:
		return "usage"
	case SubgroupCPUThrottled:
		return "throttled"
	case SubgroupMemoryLimit:
		return "limit"
	case SubgroupNetworkTxBytes:
		return "tx_bytes"
	case SubgroupNetworkRxBytes:
		return "rx_bytes"
	case SubgroupNetworkTxDropped:
		return "tx_dropped"
	case SubgroupNetworkRxDropped:
		return "rx_dropped"
	}
	return strconv.Itoa(subgroup)
}

func GroupString(group commonpb.StatsGroup) string {
	switch group {
	case commonpb.StatsGroup_STATS_GROUP_CPU:
		return "cpu"
	case commonpb.StatsGroup_STATS_GROUP_MEMORY:
		return "memory"
	case commonpb.StatsGroup_STATS_GROUP_SYSCALL:
		return "syscall"
	case commonpb.StatsGroup_STATS_GROUP_IO:
		return "io"
	case commonpb.StatsGroup_STATS_GROUP_NET:
		return "net"
	case commonpb.StatsGroup_STATS_GROUP_UNKNOWN:
		return ""
	}
	return group.String()
}
