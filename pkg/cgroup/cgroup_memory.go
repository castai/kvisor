package cgroup

import (
	"bufio"
	"errors"
	"math"
	"os"
	"strconv"
	"strings"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"golang.org/x/sys/unix"
)

func statMemoryV2(dirPath string, stats *Stats) error {
	const file = "memory.stat"
	statsFile, err := openCgroupFile(dirPath, file)
	if err != nil {
		return err
	}
	defer statsFile.Close()

	sc := bufio.NewScanner(statsFile)
	for sc.Scan() {
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
	swapUsage := swapOnlyUsage
	// As cgroup v1 reports SwapUsage values as mem+swap combined,
	// while in cgroup v2 swap values do not include memory,
	// report combined mem+swap for v1 compatibility.
	swapUsage.Usage += memoryUsage.Usage
	if swapUsage.Limit != math.MaxUint64 {
		swapUsage.Limit += memoryUsage.Limit
	}
	stats.MemoryStats.SwapUsage = swapUsage

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
	statsFile, err := openCgroupFile(dirPath, file)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer statsFile.Close()

	sc := bufio.NewScanner(statsFile)
	for sc.Scan() {
		t, v, err := parseKeyValue(sc.Text())
		if err != nil {
			return &parseError{Path: dirPath, File: file, Err: err}
		}
		if t == "cache" {
			stats.MemoryStats.Cache = v
		}
	}

	memoryUsage, err := getMemoryDataV1(dirPath, "") // TODO: Why empty?
	if err != nil {
		return err
	}
	stats.MemoryStats.Usage = memoryUsage
	swapUsage, err := getMemoryDataV1(dirPath, "memsw")
	if err != nil {
		return err
	}
	stats.MemoryStats.SwapUsage = swapUsage
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

var _ = rootStatsFromMeminfo

func rootStatsFromMeminfo(stats *Stats) error {
	const file = "/proc/meminfo"
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()

	// Fields we are interested in.
	var (
		swap_free  uint64
		swap_total uint64
	)
	mem := map[string]*uint64{
		"SwapFree":  &swap_free,
		"SwapTotal": &swap_total,
	}

	found := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), ":", 3)
		if len(parts) != 2 {
			// Should not happen.
			continue
		}
		k := parts[0]
		p, ok := mem[k]
		if !ok {
			// Unknown field -- not interested.
			continue
		}
		vStr := strings.TrimSpace(strings.TrimSuffix(parts[1], " kB"))
		*p, err = strconv.ParseUint(vStr, 10, 64)
		if err != nil {
			return &parseError{File: file, Err: errors.New("bad value for " + k)}
		}

		found++
		if found == len(mem) {
			// Got everything we need -- skip the rest.
			break
		}
	}
	if err := sc.Err(); err != nil {
		return &parseError{Path: "", File: file, Err: err}
	}

	// cgroup v1 `usage_in_bytes` reports memory usage as the sum of
	// - rss (NR_ANON_MAPPED)
	// - cache (NR_FILE_PAGES)
	// cgroup v1 reports SwapUsage values as mem+swap combined
	// cgroup v2 reports rss and cache as anon and file.
	// sum `anon` + `file` to report the same value as `usage_in_bytes` in v1.
	// sum swap usage as combined mem+swap usage for consistency as well.
	//stats.MemoryStats.Usage.Usage = stats.MemoryStats.Stats["anon"] + stats.MemoryStats.Stats["file"] // TODO: Add this.
	stats.MemoryStats.Usage.Limit = math.MaxUint64
	stats.MemoryStats.SwapUsage.Usage = (swap_total - swap_free) * 1024
	stats.MemoryStats.SwapUsage.Limit = math.MaxUint64
	stats.MemoryStats.SwapUsage.Usage += stats.MemoryStats.Usage.Usage

	return nil
}
