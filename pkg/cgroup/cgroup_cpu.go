package cgroup

import (
	"bufio"
	"os"
)

func statCpuV2(dirPath string, stats *Stats) error {
	const file = "cpu.stat"
	f, err := openCgroupFile(dirPath, file)
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		t, v, err := parseKeyValue(sc.Text())
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

func statCpuV1(dirPath string, stats *Stats) error {
	const file = "cpu.stat"
	f, err := openCgroupFile(dirPath, file)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		t, v, err := parseKeyValue(sc.Text())
		if err != nil {
			return &parseError{Path: dirPath, File: file, Err: err}
		}
		switch t {
		case "nr_throttled":
			stats.CpuStats.ThrottledPeriods = v

		case "throttled_time":
			stats.CpuStats.ThrottledTime = v
		}
	}
	return nil
}
