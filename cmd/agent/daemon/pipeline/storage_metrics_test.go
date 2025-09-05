package pipeline

import (
	"testing"
	"time"

	"github.com/shirou/gopsutil/v4/disk"
	"github.com/stretchr/testify/require"

	"github.com/castai/kvisor/pkg/logging"
)

func TestStorageMetricsRealIntegration2(t *testing.T) {
	t.Run("test collectAndSendBlockDeviceMetrics with artificial IOStats data", func(t *testing.T) {
		// Create test filesystem structure
		testDir := t.TempDir()
		setupTestSysBlockForSdaAndSdb(t, testDir)

		// Create mock block device metrics writer to capture writes
		mockBlockMetrics := &mockBlockDeviceMetricsWriter{}
		
		// Create mock disk stats provider with test data
		mockDiskStats := &mockDiskStatsProvider{
			ioCountersFunc: func() (map[string]disk.IOCountersStat, error) {
				return map[string]disk.IOCountersStat{
					"sda": {
						ReadCount:  100,
						WriteCount: 50,
						ReadBytes:  1024000,
						WriteBytes: 512000,
					},
					"sdb": {
						ReadCount:  200,
						WriteCount: 75,
						ReadBytes:  2048000,
						WriteBytes: 1024000,
					},
				}, nil
			},
		}

		// Create controller with mocks and test filesystem path
		c := Controller{
			blockDeviceMetrics: mockBlockMetrics,
			filesystemMetrics:  &mockFilesystemMetricsWriter{},
			diskStatsProvider:  mockDiskStats,
			log:                logging.NewTestLog(),
			nodeName:           "test-node",
			testSysBlockPath:   testDir, // Use test filesystem
			storageState: &storageMetricsState{
				blockDevices: make(map[string]*BlockDeviceMetrics),
				filesystems:  make(map[string]*FilesystemMetrics),
			},
		}

		// First call - should collect metrics but not write (no previous metrics)
		timestamp1 := time.Now()
		c.collectAndSendBlockDeviceMetrics(timestamp1)

		// Verify no metrics were written yet (first collection)
		require.Len(t, mockBlockMetrics.metrics, 0, "No metrics should be written on first collection")

		// Second call - should calculate rates and write metrics
		time.Sleep(10 * time.Millisecond) // Small delay to ensure time difference
		timestamp2 := timestamp1.Add(time.Second)
		
		// Update mock to return different values for rate calculation
		mockDiskStats.ioCountersFunc = func() (map[string]disk.IOCountersStat, error) {
			return map[string]disk.IOCountersStat{
				"sda": {
					ReadCount:  110,  // +10
					WriteCount: 55,   // +5
					ReadBytes:  1124000, // +100000
					WriteBytes: 562000,  // +50000
				},
				"sdb": {
					ReadCount:  220,  // +20
					WriteCount: 85,   // +10
					ReadBytes:  2248000, // +200000
					WriteBytes: 1124000, // +100000
				},
			}, nil
		}
		
		c.collectAndSendBlockDeviceMetrics(timestamp2)

		// Verify metrics were written
		require.Len(t, mockBlockMetrics.metrics, 2, "Expected 2 block device metrics to be written")

		// Verify first device (sda) metrics
		sdaMetric := mockBlockMetrics.metrics[0]
		if sdaMetric.Name == "sda" {
			require.Equal(t, "test-node", sdaMetric.NodeName)
			require.Equal(t, int64(10), sdaMetric.ReadIOPS)
			require.Equal(t, int64(5), sdaMetric.WriteIOPS)
			require.Equal(t, float64(100000), sdaMetric.ReadThroughput)
			require.Equal(t, float64(50000), sdaMetric.WriteThroughput)
		}

		// Find the sdb metric (order might vary)
		var sdbMetric *BlockDeviceMetrics
		for i := range mockBlockMetrics.metrics {
			if mockBlockMetrics.metrics[i].Name == "sdb" {
				sdbMetric = &mockBlockMetrics.metrics[i]
				break
			}
		}
		require.NotNil(t, sdbMetric, "sdb metric should be present")
		require.Equal(t, "test-node", sdbMetric.NodeName)
		require.Equal(t, int64(20), sdbMetric.ReadIOPS)
		require.Equal(t, int64(10), sdbMetric.WriteIOPS)
		require.Equal(t, float64(200000), sdbMetric.ReadThroughput)
		require.Equal(t, float64(100000), sdbMetric.WriteThroughput)
		
		// Verify disk size was calculated from test filesystem (1GB = 1073741824 bytes)
		require.Equal(t, int64(1073741824), sdbMetric.Size, "sdb should have 1GB disk size from test filesystem")
		// Verify physical devices - sdb should resolve to itself
		require.Equal(t, []string{"/dev/sdb"}, sdbMetric.PhysicalDevices, "sdb should resolve to physical device /dev/sdb")

		// Verify sda metric disk size and physical devices as well
		if sdaMetric.Name == "sda" {
			// Verify disk size was calculated from test filesystem (512MB = 536870912 bytes)
			require.Equal(t, int64(536870912), sdaMetric.Size, "sda should have 512MB disk size from test filesystem")
			// Verify physical devices - sda should resolve to itself
			require.Equal(t, []string{"/dev/sda"}, sdaMetric.PhysicalDevices, "sda should resolve to physical device /dev/sda")
		}
	})

	t.Run("test disk size collection and physical devices with test filesystem", func(t *testing.T) {
		// Create test filesystem structure
		testDir := t.TempDir()
		setupTestSysBlockWithPartitions(t, testDir)
		setupTestLVMStructure(t, testDir)

		// Create mock block device metrics writer to capture writes
		mockBlockMetrics := &mockBlockDeviceMetricsWriter{}
		
		// Create mock disk stats provider with test data
		mockDiskStats := &mockDiskStatsProvider{
			ioCountersFunc: func() (map[string]disk.IOCountersStat, error) {
				return map[string]disk.IOCountersStat{
					"sda": {
						ReadCount:  100,
						WriteCount: 50,
						ReadBytes:  1024000,
						WriteBytes: 512000,
					},
					"dm-0": {
						ReadCount:  200,
						WriteCount: 75,
						ReadBytes:  2048000,
						WriteBytes: 1024000,
					},
				}, nil
			},
		}

		// Create controller with mocks and test filesystem path
		c := Controller{
			blockDeviceMetrics: mockBlockMetrics,
			filesystemMetrics:  &mockFilesystemMetricsWriter{},
			diskStatsProvider:  mockDiskStats,
			log:                logging.NewTestLog(),
			nodeName:           "test-node",
			testSysBlockPath:   testDir, // Use test filesystem
			storageState: &storageMetricsState{
				blockDevices: make(map[string]*BlockDeviceMetrics),
				filesystems:  make(map[string]*FilesystemMetrics),
			},
		}

		// First call to collect initial metrics
		timestamp1 := time.Now()
		c.collectAndSendBlockDeviceMetrics(timestamp1)

		// Verify no metrics were written on first collection
		require.Len(t, mockBlockMetrics.metrics, 0, "No metrics should be written on first collection")

		// Second call - should calculate rates and write metrics with disk sizes and physical devices
		time.Sleep(10 * time.Millisecond) 
		timestamp2 := timestamp1.Add(time.Second)
		
		// Update mock to return different values for rate calculation
		mockDiskStats.ioCountersFunc = func() (map[string]disk.IOCountersStat, error) {
			return map[string]disk.IOCountersStat{
				"sda": {
					ReadCount:  110,
					WriteCount: 55,
					ReadBytes:  1124000,
					WriteBytes: 562000,
				},
				"dm-0": {
					ReadCount:  220,
					WriteCount: 85,
					ReadBytes:  2248000,
					WriteBytes: 1124000,
				},
			}, nil
		}
		
		c.collectAndSendBlockDeviceMetrics(timestamp2)

		// Verify metrics were written
		require.Len(t, mockBlockMetrics.metrics, 2, "Expected 2 block device metrics to be written")

		// Find and verify sda metric (physical device)
		var sdaMetric *BlockDeviceMetrics
		for i := range mockBlockMetrics.metrics {
			if mockBlockMetrics.metrics[i].Name == "sda" {
				sdaMetric = &mockBlockMetrics.metrics[i]
				break
			}
		}
		require.NotNil(t, sdaMetric, "sda metric should be present")
		require.Equal(t, "test-node", sdaMetric.NodeName)
		require.Equal(t, int64(10), sdaMetric.ReadIOPS)
		require.Equal(t, int64(5), sdaMetric.WriteIOPS)
		require.Equal(t, float64(100000), sdaMetric.ReadThroughput)
		require.Equal(t, float64(50000), sdaMetric.WriteThroughput)
		// Verify disk size was calculated (1GB = 1073741824 bytes)
		require.Equal(t, int64(1073741824), sdaMetric.Size, "sda should have 1GB disk size")
		// Physical devices - sda should resolve to itself
		require.Equal(t, []string{"/dev/sda"}, sdaMetric.PhysicalDevices)

		// Find and verify dm-0 metric (LVM device)
		var dm0Metric *BlockDeviceMetrics
		for i := range mockBlockMetrics.metrics {
			if mockBlockMetrics.metrics[i].Name == "dm-0" {
				dm0Metric = &mockBlockMetrics.metrics[i]
				break
			}
		}
		require.NotNil(t, dm0Metric, "dm-0 metric should be present")
		require.Equal(t, "test-node", dm0Metric.NodeName)
		require.Equal(t, int64(20), dm0Metric.ReadIOPS)
		require.Equal(t, int64(10), dm0Metric.WriteIOPS)
		require.Equal(t, float64(200000), dm0Metric.ReadThroughput)
		require.Equal(t, float64(100000), dm0Metric.WriteThroughput)
		// Verify disk size was calculated (2GB = 2147483648 bytes)
		require.Equal(t, int64(2147483648), dm0Metric.Size, "dm-0 should have 2GB disk size")
		// Physical devices - dm-0 should resolve to sdb and sdc
		require.Len(t, dm0Metric.PhysicalDevices, 2, "dm-0 should have 2 physical devices")
		require.Contains(t, dm0Metric.PhysicalDevices, "/dev/sdb")
		require.Contains(t, dm0Metric.PhysicalDevices, "/dev/sdc")
	})
}
