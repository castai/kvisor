package cgroup

import (
	"errors"
	"os"
	"path"
	"strings"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
)

const UnifiedMountpoint = "/sys/fs/cgroup"

var ErrStatsNotFound = errors.New("stats not found")

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
			// Most likely container was deleted.
			return res, ErrStatsNotFound
		}
		return res, err
	}
	return res, nil
}

// newCgroupStatsGetterFunc returns a function that reads cgroup stats.
//
// This function should be called only once during initial cgroup insertion into our cache.
// It allows to cache some more expensive file paths join operations once.
func newCgroupStatsGetterFunc(version Version, psiEnabled bool, cgRootfsPath, cgPath string) func(stats *Stats) error {
	switch version {
	case V1:
		rest := getCgroupV1Path(cgRootfsPath, cgPath)
		memBasePath := path.Join(cgRootfsPath, "memory", rest)
		cpuBasePath := path.Join(cgRootfsPath, "cpu", rest)
		cpuAcctBasePath := path.Join(cgRootfsPath, "cpuacct", rest)
		pidsBasePath := path.Join(cgRootfsPath, "pids", rest)

		return func(stats *Stats) error {
			if err := statMemoryV1(memBasePath, stats); err != nil {
				return err
			}
			if err := statCpuV1(cpuBasePath, cpuAcctBasePath, stats); err != nil {
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

// getCgroupV1Path returns the cgroup path without root cgroup path and subsystem.
// During metrics scrape actual subsystems are added back to the full path.
func getCgroupV1Path(cgRootfsPath, cgPath string) string {
	cgPath, _ = strings.CutPrefix(cgPath, cgRootfsPath)
	var sepCount int
	for i, c := range cgPath {
		if c == '/' {
			sepCount++
		}
		if sepCount == 2 {
			return cgPath[i+1:]
		}
	}
	return ""
}
