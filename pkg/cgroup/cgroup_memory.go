package cgroup

import (
	"bufio"
	"errors"
	"os"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"golang.org/x/sys/unix"
)

func statMemoryV2(dirPath string, stats *Stats) error {
	const file = "memory.stat"
	statsFile, err := openFile(dirPath, file)
	if err != nil {
		return err
	}
	defer statsFile.Close()

	sc := bufio.NewScanner(statsFile)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		t, v, err := parseKeyValue(sc.Text())
		if err != nil {
			return &parseError{Path: dirPath, File: file, Err: err}
		}
		if t == "file" {
			stats.MemoryStats.Cache = v
		}
	}
	if err := sc.Err(); err != nil {
		return &parseError{Path: dirPath, File: file, Err: err}
	}

	memoryUsage, err := getMemoryDataV2(dirPath, "")
	if err != nil {
		if errors.Is(err, unix.ENOENT) && dirPath == UnifiedMountpoint {
			// The root cgroup does not have memory.{current,max,peak}
			return nil
		}
		return err
	}
	stats.MemoryStats.Usage = memoryUsage
	swapOnlyUsage, err := getMemoryDataV2(dirPath, "swap")
	if err != nil {
		return err
	}
	stats.MemoryStats.SwapOnlyUsage = swapOnlyUsage

	return nil
}

func getMemoryDataV2(path, name string) (*castaipb.MemoryData, error) {
	memoryData := castaipb.MemoryData{}

	moduleName := "memory"
	if name != "" {
		moduleName = "memory." + name
	}
	usage := moduleName + ".current"
	limit := moduleName + ".max"

	value, err := getCgroupParamUint(path, usage)
	if err != nil {
		if name != "" && os.IsNotExist(err) {
			// Ignore EEXIST as there's no swap accounting
			// if kernel CONFIG_MEMCG_SWAP is not set or
			// swapaccount=0 kernel boot parameter is given.
			return &memoryData, nil
		}
		return nil, err
	}
	memoryData.Usage = value

	value, err = getCgroupParamUint(path, limit)
	if err != nil {
		return nil, err
	}
	memoryData.Limit = value
	return &memoryData, nil
}

func statMemoryV1(dirPath string, stats *Stats) error {
	const file = "memory.stat"
	statsFile, err := openFile(dirPath, file)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer statsFile.Close()

	sc := bufio.NewScanner(statsFile)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		t, v, err := parseKeyValue(line)
		if err != nil {
			return &parseError{Path: dirPath, File: file, Err: err}
		}
		if t == "cache" {
			stats.MemoryStats.Cache = v
		}
	}

	memoryUsage, err := getMemoryDataV1(dirPath, "")
	if err != nil {
		return err
	}
	stats.MemoryStats.Usage = memoryUsage
	swapUsage, err := getMemoryDataV1(dirPath, "memsw")
	if err != nil {
		return err
	}
	stats.MemoryStats.SwapOnlyUsage = &castaipb.MemoryData{
		Usage: swapUsage.Usage - memoryUsage.Usage,
	}
	return nil
}

func getMemoryDataV1(path, name string) (*castaipb.MemoryData, error) {
	memoryData := castaipb.MemoryData{}

	moduleName := "memory"
	if name != "" {
		moduleName = "memory." + name
	}
	var (
		usage = moduleName + ".usage_in_bytes"
		limit = moduleName + ".limit_in_bytes"
	)

	value, err := getCgroupParamUint(path, usage)
	if err != nil {
		if name != "" && os.IsNotExist(err) {
			// Ignore ENOENT as swap and kmem controllers
			// are optional in the kernel.
			return &memoryData, nil
		}
		return nil, err
	}
	memoryData.Usage = value
	value, err = getCgroupParamUint(path, limit)
	if err != nil {
		if name == "kmem" && os.IsNotExist(err) {
			// Ignore ENOENT as kmem.limit_in_bytes has
			// been removed in newer kernels.
			return &memoryData, nil
		}

		return nil, err
	}
	memoryData.Limit = value

	return &memoryData, nil
}
