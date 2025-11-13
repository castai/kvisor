package pipeline

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// DiskStats represents raw I/O statistics from /proc/diskstats
type DiskStats struct {
	Name         string
	ReadIOs      uint64
	ReadMerges   uint64
	ReadSectors  uint64
	ReadTicks    uint64
	WriteIOs     uint64
	WriteMerges  uint64
	WriteSectors uint64
	WriteTicks   uint64
	InFlight     uint64
	IOTicks      uint64
	TimeInQueue  uint64
	Timestamp    time.Time
}

// isDiscoverableDevice returns true if the device should be included in metrics
// Filters out loop and ram devices
func isDiscoverableDevice(deviceName string) bool {
	return !strings.HasPrefix(deviceName, "loop") &&
		!strings.HasPrefix(deviceName, "ram")
}

const procDiskStatsPath = "/proc/diskstats"

// readProcDiskStats reads and parses /proc/diskstats
// Returns a map of device name -> DiskStats
func readProcDiskStats() (map[string]DiskStats, error) {
	f, err := os.Open(procDiskStatsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", procDiskStatsPath, err)
	}
	defer f.Close()

	timestamp := time.Now().UTC()
	stats := make(map[string]DiskStats)

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 14 {
			// Malformed line, skip it
			continue
		}

		deviceName := fields[2]

		// Filter out loop and ram devices
		if !isDiscoverableDevice(deviceName) {
			continue
		}

		// Parse fields
		readIOs, err := strconv.ParseUint(fields[3], 10, 64)
		if err != nil {
			continue
		}
		readMerges, err := strconv.ParseUint(fields[4], 10, 64)
		if err != nil {
			continue
		}
		readSectors, err := strconv.ParseUint(fields[5], 10, 64)
		if err != nil {
			continue
		}
		readTicks, err := strconv.ParseUint(fields[6], 10, 64)
		if err != nil {
			continue
		}
		writeIOs, err := strconv.ParseUint(fields[7], 10, 64)
		if err != nil {
			continue
		}
		writeMerges, err := strconv.ParseUint(fields[8], 10, 64)
		if err != nil {
			continue
		}
		writeSectors, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			continue
		}
		writeTicks, err := strconv.ParseUint(fields[10], 10, 64)
		if err != nil {
			continue
		}
		inFlight, err := strconv.ParseUint(fields[11], 10, 64)
		if err != nil {
			continue
		}
		ioTicks, err := strconv.ParseUint(fields[12], 10, 64)
		if err != nil {
			continue
		}
		timeInQueue, err := strconv.ParseUint(fields[13], 10, 64)
		if err != nil {
			continue
		}

		stats[deviceName] = DiskStats{
			Name:         deviceName,
			ReadIOs:      readIOs,
			ReadMerges:   readMerges,
			ReadSectors:  readSectors,
			ReadTicks:    readTicks,
			WriteIOs:     writeIOs,
			WriteMerges:  writeMerges,
			WriteSectors: writeSectors,
			WriteTicks:   writeTicks,
			InFlight:     inFlight,
			IOTicks:      ioTicks,
			TimeInQueue:  timeInQueue,
			Timestamp:    timestamp,
		}
	}

	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("error scanning %s: %w", procDiskStatsPath, err)
	}

	return stats, nil
}
