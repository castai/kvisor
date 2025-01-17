package cgroup

import (
	"os"
	"path"
	"strings"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
)

const UnifiedMountpoint = "/sys/fs/cgroup"

type Stats struct {
	CpuStats    *castaipb.CpuStats
	MemoryStats *castaipb.MemoryStats
	PidsStats   *castaipb.PidsStats
	IOStats     *castaipb.IOStats
}

type Cgroup struct {
	Id               uint64
	ContainerRuntime ContainerRuntimeID
	ContainerID      string

	statsGetterFunc func(stats *Stats) error
}

func (cg *Cgroup) GetStats() (Stats, error) {
	res := Stats{
		CpuStats:    &castaipb.CpuStats{},
		MemoryStats: &castaipb.MemoryStats{},
		PidsStats:   &castaipb.PidsStats{},
		IOStats:     &castaipb.IOStats{},
	}
	if err := cg.statsGetterFunc(&res); err != nil {
		if os.IsNotExist(err) {
			return res, nil
		}
		return res, err
	}
	return res, nil
}

func newCgroupStatsGetterFunc(version Version, psiEnabled bool, cgRootfsPath, cgPath string) func(stats *Stats) error {
	switch version {
	case V1:
		after, _ := strings.CutPrefix(cgPath, cgRootfsPath)
		subpath := strings.SplitN(after, "/", 1)
		if len(subpath) != 2 {
			return func(stats *Stats) error {
				return nil
			}
		}
		last := subpath[1]
		memBasePath := path.Join(cgRootfsPath, "memory", last)
		cpuBasePath := path.Join(cgRootfsPath, "cpu", last)
		pidsBasePath := path.Join(cgRootfsPath, "pids", last)
		return func(stats *Stats) error {
			if err := statMemoryV1(memBasePath, stats); err != nil {
				return err
			}
			if err := statCpuV1(cpuBasePath, stats); err != nil {
				return err
			}
			if err := statPidsV1(pidsBasePath, stats); err != nil {
				return err
			}
			return nil
		}
	case V2:
		return func(stats *Stats) error {
			if err := statMemoryV2(cgPath, stats); err != nil {
				return err
			}
			if err := statCpuV2(cgPath, stats); err != nil {
				return err
			}
			if err := statPidsV2(cgPath, stats); err != nil {
				return err
			}

			if psiEnabled {
				memPSI, _ := StatPSI(cgPath, "memory.pressure")
				stats.MemoryStats.Psi = memPSI

				cpuPSI, _ := StatPSI(cgPath, "cpu.pressure")
				stats.CpuStats.Psi = cpuPSI

				ioPSI, _ := StatPSI(cgPath, "io.pressure")
				stats.IOStats.Psi = ioPSI
			}
			return nil
		}
	}

	return func(stats *Stats) error {
		return nil
	}
}
