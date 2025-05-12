package cgroup

import (
	"testing"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/stretchr/testify/require"
)

func TestCgroupStats(t *testing.T) {
	t.Run("cgroup v1", func(t *testing.T) {
		r := require.New(t)
		statsFn := newCgroupStatsGetterFunc(V1, false, "fixtures/cgroup", "fixtures/cgroup/cpuacct/docker/b43d92bf1e5c6f78bb9b7bc6f40721280299855ba692092716e3a1b6c0b86f3f")
		res := Stats{
			CpuStats: &castaipb.CpuStats{},
			MemoryStats: &castaipb.MemoryStats{
				Usage: &castaipb.MemoryData{},
			},
		}
		r.NoError(statsFn(&res))
		r.Equal(107292866812141, int(res.CpuStats.TotalUsage))
		r.Equal(5583849, int(res.CpuStats.ThrottledPeriods))
		r.Equal(254005032764376, int(res.CpuStats.ThrottledTime))
		r.Equal(21474836410, int(res.MemoryStats.Usage.Usage))
	})

	t.Run("cgroup v2", func(t *testing.T) {
		r := require.New(t)
		statsFn := newCgroupStatsGetterFunc(V2, true, "fixtures/cgroup", "fixtures/cgroup/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod8712f785_1a3e_41ec_a00b_e2dcc77431cb.slice/docker-73051af271105c07e1f493b34856a77e665e3b0b4fc72f76c807dfbffeb881bd.scope")
		res := Stats{
			CpuStats:    &castaipb.CpuStats{},
			MemoryStats: &castaipb.MemoryStats{},
			IOStats:     &castaipb.IOStats{},
		}
		r.NoError(statsFn(&res))
		r.Equal(3795681254000, int(res.CpuStats.TotalUsage))
		r.Equal(76, int(res.CpuStats.ThrottledPeriods))
		r.Equal(363166000, int(res.CpuStats.ThrottledTime))
		r.Equal(48648192, int(res.MemoryStats.Usage.Usage))
	})
}
