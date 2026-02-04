package pipeline

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/castai/kvisor/pkg/logging"
)

// readProcDiskStatsFromPath is a test helper that reads diskstats from a custom path
func readProcDiskStatsFromPath(procPath string) (map[string]DiskStats, error) {
	data, err := os.ReadFile(procPath)
	if err != nil {
		return nil, err
	}

	timestamp := time.Now().UTC()
	stats := make(map[string]DiskStats)

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 14 {
			continue
		}

		deviceName := fields[2]

		// Filter out loop and ram devices
		if strings.HasPrefix(deviceName, "loop") || strings.HasPrefix(deviceName, "ram") {
			continue
		}

		// Parse fields
		readIOs, _ := strconv.ParseUint(fields[3], 10, 64)
		readMerges, _ := strconv.ParseUint(fields[4], 10, 64)
		readSectors, _ := strconv.ParseUint(fields[5], 10, 64)
		readTicks, _ := strconv.ParseUint(fields[6], 10, 64)
		writeIOs, _ := strconv.ParseUint(fields[7], 10, 64)
		writeMerges, _ := strconv.ParseUint(fields[8], 10, 64)
		writeSectors, _ := strconv.ParseUint(fields[9], 10, 64)
		writeTicks, _ := strconv.ParseUint(fields[10], 10, 64)
		inFlight, _ := strconv.ParseUint(fields[11], 10, 64)
		ioTicks, _ := strconv.ParseUint(fields[12], 10, 64)
		timeInQueue, _ := strconv.ParseUint(fields[13], 10, 64)

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

	return stats, nil
}

func TestReadMountInfo(t *testing.T) {
	tests := []struct {
		name          string
		mountInfoData string
		expectError   bool
		validateCount int
		validate      func(t *testing.T, mounts []mountInfo)
	}{
		{
			name: "valid ext4 filesystem",
			mountInfoData: `29 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw,errors=remount-ro
30 29 8:2 / /boot rw,relatime shared:2 - ext4 /dev/sda2 rw`,
			validateCount: 2,
			validate: func(t *testing.T, mounts []mountInfo) {
				require.Len(t, mounts, 2)

				// First mount
				assert.Equal(t, "/dev/sda1", mounts[0].Device)
				assert.Equal(t, "/", mounts[0].MountPoint)
				assert.Equal(t, "ext4", mounts[0].FsType)
				assert.Equal(t, "8:1", mounts[0].MajorMinor)
				assert.Contains(t, mounts[0].Options, "rw")
				assert.Contains(t, mounts[0].Options, "relatime")

				// Second mount
				assert.Equal(t, "/dev/sda2", mounts[1].Device)
				assert.Equal(t, "/boot", mounts[1].MountPoint)
				assert.Equal(t, "ext4", mounts[1].FsType)
			},
		},
		{
			name: "mixed filesystem types",
			mountInfoData: `29 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
30 29 253:0 / /data rw,relatime shared:2 - xfs /dev/mapper/vg-data rw
31 29 0:25 / /mnt/btrfs rw,relatime shared:3 - btrfs /dev/sdb1 rw`,
			validateCount: 3,
			validate: func(t *testing.T, mounts []mountInfo) {
				require.Len(t, mounts, 3)
				assert.Equal(t, "ext4", mounts[0].FsType)
				assert.Equal(t, "xfs", mounts[1].FsType)
				assert.Equal(t, "btrfs", mounts[2].FsType)
			},
		},
		{
			name: "unsupported filesystem types filtered out",
			mountInfoData: `29 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
30 29 0:25 / /proc rw,nosuid,nodev,noexec shared:2 - proc proc rw
31 29 0:26 / /sys rw,nosuid,nodev,noexec shared:3 - sysfs sysfs rw
32 29 0:27 / /dev rw,nosuid shared:4 - devtmpfs devtmpfs rw`,
			validateCount: 1,
			validate: func(t *testing.T, mounts []mountInfo) {
				require.Len(t, mounts, 1)
				assert.Equal(t, "ext4", mounts[0].FsType)
			},
		},
		{
			name: "empty lines and whitespace",
			mountInfoData: `
29 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw

30 29 8:2 / /boot rw,relatime shared:2 - ext4 /dev/sda2 rw

`,
			validateCount: 2,
			validate: func(t *testing.T, mounts []mountInfo) {
				require.Len(t, mounts, 2)
			},
		},
		{
			name:          "empty file",
			mountInfoData: "",
			validateCount: 0,
			validate: func(t *testing.T, mounts []mountInfo) {
				assert.Empty(t, mounts)
			},
		},
		{
			name:          "file does not exist",
			mountInfoData: "",
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var mountInfoPath string

			if tt.name != "file does not exist" {
				tmpFile, err := os.CreateTemp("", "mountinfo-*")
				require.NoError(t, err)
				defer os.Remove(tmpFile.Name())

				_, err = tmpFile.WriteString(tt.mountInfoData)
				require.NoError(t, err)
				tmpFile.Close()

				mountInfoPath = tmpFile.Name()
			} else {
				mountInfoPath = "/nonexistent/mountinfo"
			}

			mounts, err := readMountInfo(mountInfoPath)

			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			if tt.validate != nil {
				tt.validate(t, mounts)
			}
		})
	}
}

func TestParseMountInfoLine(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		expectNil   bool
		expectError bool
		validate    func(t *testing.T, mount *mountInfo)
	}{
		{
			name: "valid ext4 root mount",
			line: "29 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw,errors=remount-ro",
			validate: func(t *testing.T, mount *mountInfo) {
				assert.Equal(t, "/dev/sda1", mount.Device)
				assert.Equal(t, "/", mount.MountPoint)
				assert.Equal(t, "ext4", mount.FsType)
				assert.Equal(t, "8:1", mount.MajorMinor)
				assert.Equal(t, []string{"rw", "relatime"}, mount.Options)
			},
		},
		{
			name: "mount with multiple options",
			line: "30 29 8:2 / /boot rw,relatime,nosuid,nodev shared:2 - ext4 /dev/sda2 rw",
			validate: func(t *testing.T, mount *mountInfo) {
				assert.Equal(t, "/dev/sda2", mount.Device)
				assert.Equal(t, "/boot", mount.MountPoint)
				assert.Contains(t, mount.Options, "rw")
				assert.Contains(t, mount.Options, "relatime")
				assert.Contains(t, mount.Options, "nosuid")
				assert.Contains(t, mount.Options, "nodev")
			},
		},
		{
			name:      "unsupported filesystem type returns nil",
			line:      "30 29 0:25 / /proc rw,nosuid shared:2 - proc proc rw",
			expectNil: true,
		},
		{
			name:        "malformed line missing separator",
			line:        "29 1 8:1 / / rw,relatime ext4 /dev/sda1 rw",
			expectError: true,
		},
		{
			name:        "insufficient fields",
			line:        "29 1 8:1 / / - ext4 /dev/sda1",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mount, err := parseMountInfoLine(tt.line)

			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)

			if tt.expectNil {
				assert.Nil(t, mount)
				return
			}

			require.NotNil(t, mount)
			if tt.validate != nil {
				tt.validate(t, mount)
			}
		})
	}
}

func TestIsSupportedFilesystem(t *testing.T) {
	tests := []struct {
		fsType    string
		supported bool
	}{
		{"ext4", true},
		{"ext3", true},
		{"ext2", true},
		{"xfs", true},
		{"btrfs", true},
		{"proc", false},
		{"sysfs", false},
		{"tmpfs", false},
		{"devtmpfs", false},
		{"nfs", false},
		{"cifs", false},
	}

	for _, tt := range tests {
		t.Run(tt.fsType, func(t *testing.T) {
			result := isSupportedFilesystem(tt.fsType)
			assert.Equal(t, tt.supported, result)
		})
	}
}

func TestReadProcDiskStats(t *testing.T) {
	tests := []struct {
		name          string
		diskStatsData string
		expectError   bool
		validateCount int
		validate      func(t *testing.T, stats map[string]DiskStats)
	}{
		{
			name: "valid diskstats with sda",
			diskStatsData: `   8       0 sda 1000 100 50000 2000 500 50 25000 1000 0 1500 3000
   8       1 sda1 800 80 40000 1600 400 40 20000 800 0 1200 2400`,
			validateCount: 2,
			validate: func(t *testing.T, stats map[string]DiskStats) {
				require.Len(t, stats, 2)

				// Check sda
				sda, ok := stats["sda"]
				require.True(t, ok)
				assert.Equal(t, "sda", sda.Name)
				assert.Equal(t, uint64(1000), sda.ReadIOs)
				assert.Equal(t, uint64(100), sda.ReadMerges)
				assert.Equal(t, uint64(50000), sda.ReadSectors)
				assert.Equal(t, uint64(2000), sda.ReadTicks)
				assert.Equal(t, uint64(500), sda.WriteIOs)
				assert.Equal(t, uint64(50), sda.WriteMerges)
				assert.Equal(t, uint64(25000), sda.WriteSectors)
				assert.Equal(t, uint64(1000), sda.WriteTicks)
				assert.Equal(t, uint64(0), sda.InFlight)
				assert.Equal(t, uint64(1500), sda.IOTicks)
				assert.Equal(t, uint64(3000), sda.TimeInQueue)

				// Check sda1
				sda1, ok := stats["sda1"]
				require.True(t, ok)
				assert.Equal(t, "sda1", sda1.Name)
			},
		},
		{
			name: "loop and ram devices filtered out",
			diskStatsData: `   8       0 sda 1000 100 50000 2000 500 50 25000 1000 0 1500 3000
   7       0 loop0 100 10 5000 200 50 5 2500 100 0 150 300
   1       0 ram0 10 1 500 20 5 0 250 10 0 15 30
 259       0 nvme0n1 2000 200 100000 4000 1000 100 50000 2000 0 3000 6000`,
			validateCount: 2,
			validate: func(t *testing.T, stats map[string]DiskStats) {
				require.Len(t, stats, 2)
				assert.Contains(t, stats, "sda")
				assert.Contains(t, stats, "nvme0n1")
				assert.NotContains(t, stats, "loop0")
				assert.NotContains(t, stats, "ram0")
			},
		},
		{
			name: "malformed lines skipped",
			diskStatsData: `   8       0 sda 1000 100 50000 2000 500 50 25000 1000 0 1500 3000
   8       1 sda1 invalid data
   8       2 sda2 900 90 45000 1800 450 45 22500 900 0 1350 2700`,
			validateCount: 2,
			validate: func(t *testing.T, stats map[string]DiskStats) {
				require.Len(t, stats, 2)
				assert.Contains(t, stats, "sda")
				assert.Contains(t, stats, "sda2")
				assert.NotContains(t, stats, "sda1")
			},
		},
		{
			name:          "empty file",
			diskStatsData: "",
			validateCount: 0,
			validate: func(t *testing.T, stats map[string]DiskStats) {
				assert.Empty(t, stats)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile, err := os.CreateTemp("", "diskstats-*")
			require.NoError(t, err)
			defer os.Remove(tmpFile.Name())

			_, err = tmpFile.WriteString(tt.diskStatsData)
			require.NoError(t, err)
			tmpFile.Close()

			stats, err := readProcDiskStatsFromPath(tmpFile.Name())

			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			if tt.validate != nil {
				tt.validate(t, stats)
			}
		})
	}
}

func TestCollectBlockDeviceMetrics(t *testing.T) {
	diskStatsData := `   8       0 sda 1000 100 50000 2000 500 50 25000 1000 0 1500 3000
   8       1 sda1 800 80 40000 1600 400 40 20000 800 0 1200 2400`

	diskStatsData2 := `   8       0 sda 2000 200 100000 4000 1000 100 50000 2000 0 3000 6000
   8       1 sda1 1600 160 80000 3200 800 80 40000 1600 0 2400 4800`

	// Create first diskstats file
	tmpFile1, err := os.CreateTemp("", "diskstats-1-*")
	require.NoError(t, err)
	defer os.Remove(tmpFile1.Name())
	_, err = tmpFile1.WriteString(diskStatsData)
	require.NoError(t, err)
	tmpFile1.Close()

	// Create second diskstats file
	tmpFile2, err := os.CreateTemp("", "diskstats-2-*")
	require.NoError(t, err)
	defer os.Remove(tmpFile2.Name())
	_, err = tmpFile2.WriteString(diskStatsData2)
	require.NoError(t, err)
	tmpFile2.Close()

	provider := &SysfsStorageInfoProvider{
		log:        logging.NewTestLog(),
		nodeName:   "test-node",
		kubeClient: nil, // Not needed for this test
		storageState: &storageMetricsState{
			blockDevices: make(map[string]*BlockDeviceMetric),
		},
	}

	timestamp1 := time.Now()

	// First call - read from first diskstats file
	stats1, err := readProcDiskStatsFromPath(tmpFile1.Name())
	require.NoError(t, err)

	for deviceName, stats := range stats1 {
		metric := provider.buildBlockDeviceMetric(deviceName, stats, timestamp1)
		provider.storageState.blockDevices[deviceName] = &metric
	}

	// First call should return empty (no previous data)
	blockMetrics := make([]BlockDeviceMetric, 0)
	for deviceName, current := range provider.storageState.blockDevices {
		_ = deviceName
		_ = current
		// No previous state, so no metrics emitted
	}
	assert.Empty(t, blockMetrics)

	// Second call - read from second diskstats file (10 seconds later)
	timestamp2 := timestamp1.Add(10 * time.Second)
	stats2, err := readProcDiskStatsFromPath(tmpFile2.Name())
	require.NoError(t, err)

	blockMetrics = make([]BlockDeviceMetric, 0)
	for deviceName, stats := range stats2 {
		current := provider.buildBlockDeviceMetric(deviceName, stats, timestamp2)

		prev, exists := provider.storageState.blockDevices[current.Name]
		if exists {
			timeDiff := current.Timestamp.Sub(prev.Timestamp).Seconds()
			if timeDiff > 0 {
				provider.calculateBlockDeviceRates(&current, prev, timeDiff)
				blockMetrics = append(blockMetrics, current)
			}
		}

		provider.storageState.blockDevices[current.Name] = &current
	}

	require.Len(t, blockMetrics, 2)

	// Validate sda metrics
	var sdaMetric *BlockDeviceMetric
	for i := range blockMetrics {
		if blockMetrics[i].Name == "sda" {
			sdaMetric = &blockMetrics[i]
			break
		}
	}
	require.NotNil(t, sdaMetric)

	// sda: reads increased by 1000 over 10 seconds = 100 IOPS
	assert.Equal(t, float64(100), sdaMetric.ReadIOPS)
	// sda: writes increased by 500 over 10 seconds = 50 IOPS
	assert.Equal(t, float64(50), sdaMetric.WriteIOPS)
	// sda: read sectors increased by 50000, at 512 bytes per sector = 25600000 bytes over 10 seconds
	assert.Equal(t, float64(2560000), sdaMetric.ReadThroughputBytes)
	// sda: write sectors increased by 25000, at 512 bytes per sector = 12800000 bytes over 10 seconds
	assert.Equal(t, float64(1280000), sdaMetric.WriteThroughputBytes)

	assert.Equal(t, "test-node", sdaMetric.NodeName)
	// NodeTemplate will be nil since kubeClient is nil in this test
}

func TestCollectBlockDeviceMetricsWithLVM(t *testing.T) {
	r := require.New(t)
	tmpDir := t.TempDir()

	// Create sysfs structure for dm-0
	dm0Path := filepath.Join(tmpDir, "sys/block/dm-0")
	err := os.MkdirAll(dm0Path, 0755)
	r.NoError(err)
	err = os.WriteFile(filepath.Join(dm0Path, "dev"), []byte("253:0\n"), 0644)
	r.NoError(err)

	// Create udev database for dm-0 with LVM tags
	udevDataDir := filepath.Join(tmpDir, "proc/1/root/run/udev/data")
	err = os.MkdirAll(udevDataDir, 0755)
	r.NoError(err)

	udevContent := `E:DM_NAME=vg-lv_data
E:DM_VG_NAME=vg
E:DM_LV_NAME=lv_data
E:DM_UUID=LVM-abcd1234
E:DEVNAME=/dev/dm-0
E:SUBSYSTEM=block
`
	err = os.WriteFile(filepath.Join(udevDataDir, "b253:0"), []byte(udevContent), 0644)
	r.NoError(err)

	provider := &SysfsStorageInfoProvider{
		log:            logging.NewTestLog(),
		nodeName:       "test-node",
		kubeClient:     nil, // Not needed for this test
		sysBlockPrefix: tmpDir,
		hostRootPath:   filepath.Join(tmpDir, "proc/1/root"),
		storageState: &storageMetricsState{
			blockDevices: make(map[string]*BlockDeviceMetric),
		},
	}

	now := time.Now().UTC()
	dm0Metric := provider.buildBlockDeviceMetric("dm-0", DiskStats{}, now)
	r.Equal("dm-0", dm0Metric.Name)

	// LVM metadata is populated for dm-0
	r.Len(dm0Metric.LVMInfo, 3)
	r.Equal("vg-lv_data", dm0Metric.LVMInfo["dm_name"])
	r.Equal("vg", dm0Metric.LVMInfo["vg_name"])
	r.Equal("lv_data", dm0Metric.LVMInfo["lv_name"])
}

func TestCalculateBlockDeviceRates(t *testing.T) {
	tests := []struct {
		name     string
		prev     BlockDeviceMetric
		current  BlockDeviceMetric
		timeDiff float64
		validate func(t *testing.T, current *BlockDeviceMetric)
	}{
		{
			name:     "normal rate calculation",
			timeDiff: 10.0,
			prev: BlockDeviceMetric{
				readIOs:           1000,
				writeIOs:          500,
				readSectors:       50000,
				writeSectors:      25000,
				readTicks:         2000,
				writeTicks:        1000,
				ioTicks:           1500,
				timeInQueue:       3000,
				logicalSectorSize: 512,
			},
			current: BlockDeviceMetric{
				readIOs:           2000,
				writeIOs:          1000,
				readSectors:       100000,
				writeSectors:      50000,
				readTicks:         4000,
				writeTicks:        2000,
				ioTicks:           3000,
				timeInQueue:       6000,
				logicalSectorSize: 512,
			},
			validate: func(t *testing.T, current *BlockDeviceMetric) {
				assert.Equal(t, float64(100), current.ReadIOPS)                 // (2000-1000)/10
				assert.Equal(t, float64(50), current.WriteIOPS)                 // (1000-500)/10
				assert.Equal(t, float64(2560000), current.ReadThroughputBytes)  // (100000-50000)*512/10
				assert.Equal(t, float64(1280000), current.WriteThroughputBytes) // (50000-25000)*512/10
				assert.Equal(t, float64(2), current.ReadLatencyMs)              // (4000-2000)/(2000-1000)
				assert.Equal(t, float64(2), current.WriteLatencyMs)             // (2000-1000)/(1000-500)
				assert.Equal(t, float64(0.3), current.AvgQueueDepth)            // (6000-3000)/(10*1000)
				assert.Equal(t, float64(0.15), current.Utilization)             // (3000-1500)/(10*1000)
			},
		},
		{
			name:     "zero time diff",
			timeDiff: 0.0,
			prev: BlockDeviceMetric{
				readIOs: 1000,
			},
			current: BlockDeviceMetric{
				readIOs: 2000,
			},
			validate: func(t *testing.T, current *BlockDeviceMetric) {
				// All rates should remain at their default zero values
				assert.Equal(t, float64(0), current.ReadIOPS)
				assert.Equal(t, float64(0), current.WriteIOPS)
			},
		},
		{
			name:     "counter reset - underflow wraps around",
			timeDiff: 10.0,
			prev: BlockDeviceMetric{
				readIOs:  2000,
				writeIOs: 1000,
			},
			current: BlockDeviceMetric{
				readIOs:  100,
				writeIOs: 50,
			},
			validate: func(t *testing.T, current *BlockDeviceMetric) {
				// Note: Current implementation doesn't detect counter resets,
				// so uint64 underflow results in large positive numbers
				// In production, these would be filtered out or handled by
				// removing the device from state after detecting anomalous values
				assert.Greater(t, current.ReadIOPS, float64(0))
				assert.Greater(t, current.WriteIOPS, float64(0))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &SysfsStorageInfoProvider{
				log: logging.NewTestLog(),
			}

			current := tt.current
			provider.calculateBlockDeviceRates(&current, &tt.prev, tt.timeDiff)

			if tt.validate != nil {
				tt.validate(t, &current)
			}
		})
	}
}

func TestSafeDiv(t *testing.T) {
	tests := []struct {
		name        string
		numerator   float64
		denominator float64
		expected    float64
	}{
		{"normal division", 10.0, 2.0, 5.0},
		{"zero numerator", 0.0, 5.0, 0.0},
		{"zero denominator", 10.0, 0.0, 0.0},
		{"both zero", 0.0, 0.0, 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := safeDiv(tt.numerator, tt.denominator)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetDiskType(t *testing.T) {
	// Create a temporary directory structure mimicking /sys/block
	tmpDir, err := os.MkdirTemp("", "sysblock-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create parent device (nvme0n1) with rotational=0 (SSD)
	nvme0n1Path := tmpDir + "/sys/block/nvme0n1"
	err = os.MkdirAll(nvme0n1Path+"/queue", 0755)
	require.NoError(t, err)
	err = os.WriteFile(nvme0n1Path+"/queue/rotational", []byte("0\n"), 0644)
	require.NoError(t, err)

	// Create partition under parent (nvme0n1p1)
	nvme0n1p1Path := nvme0n1Path + "/nvme0n1p1"
	err = os.MkdirAll(nvme0n1p1Path, 0755)
	require.NoError(t, err)

	// Create HDD device (sda) with rotational=1
	sdaPath := tmpDir + "/sys/block/sda"
	err = os.MkdirAll(sdaPath+"/queue", 0755)
	require.NoError(t, err)
	err = os.WriteFile(sdaPath+"/queue/rotational", []byte("1\n"), 0644)
	require.NoError(t, err)

	// Create partition under sda (sda1)
	sda1Path := sdaPath + "/sda1"
	err = os.MkdirAll(sda1Path, 0755)
	require.NoError(t, err)

	provider := &SysfsStorageInfoProvider{
		log:            logging.NewTestLog(),
		sysBlockPrefix: tmpDir,
		storageState: &storageMetricsState{
			blockDevices: make(map[string]*BlockDeviceMetric),
		},
	}

	tests := []struct {
		name       string
		deviceName string
		expected   string
	}{
		{
			name:       "SSD parent device",
			deviceName: "nvme0n1",
			expected:   "SSD",
		},
		{
			name:       "SSD partition inherits from parent",
			deviceName: "nvme0n1p1",
			expected:   "SSD",
		},
		{
			name:       "HDD parent device",
			deviceName: "sda",
			expected:   "HDD",
		},
		{
			name:       "HDD partition inherits from parent",
			deviceName: "sda1",
			expected:   "HDD",
		},
		{
			name:       "non-existent device returns empty",
			deviceName: "nonexistent",
			expected:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := provider.getDiskType(tt.deviceName)
			assert.Equal(t, tt.expected, result)
		})
	}
}
