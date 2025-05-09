package cgroup

import (
	"bufio"
	"path"
)

func statCpuV2(dirPath string, stats *Stats) error {
	const file = "cpu.stat"
	f, err := openFile(dirPath, file)
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		t, v, err := parseKeyValue(line)
		if err != nil {
			return &parseError{Path: dirPath, File: file, Err: err}
		}
		switch t {
		case "usage_usec":
			stats.CpuStats.TotalUsage = v * 1000

		case "user_usec":
			stats.CpuStats.UsageInUsermode = v * 1000

		case "system_usec":
			stats.CpuStats.UsageInKernelmode = v * 1000

		case "nr_throttled":
			stats.CpuStats.ThrottledPeriods = v

		case "throttled_usec":
			stats.CpuStats.ThrottledTime = v * 1000
		}
	}
	if err := sc.Err(); err != nil {
		return &parseError{Path: dirPath, File: file, Err: err}
	}
	return nil
}

func statCpuV1(cpuFile string, cpuAcctBasePath string, stats *Stats) error {
	throttling, err := readVariablesFromFile(path.Join(cpuFile, "cpu.stat"))
	if err != nil {
		return err
	}
	stats.CpuStats.ThrottledPeriods = throttling["nr_throttled"]
	stats.CpuStats.ThrottledTime = throttling["throttled_time"]

	usageNs, err := readIntFromFile(path.Join(cpuAcctBasePath, "cpuacct.usage"))
	if err != nil {
		return err
	}
	stats.CpuStats.TotalUsage = uint64(usageNs) // nolint:gosec

	return nil
}
