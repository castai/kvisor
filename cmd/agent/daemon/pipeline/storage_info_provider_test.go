package pipeline

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/samber/lo"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	kubepb "github.com/castai/kvisor/api/v1/kube"
	"github.com/castai/kvisor/pkg/logging"
)

type mockDiskClient struct {
	partitions    []disk.PartitionStat
	partitionsErr error
	diskStatsMap  map[string]*disk.UsageStat
	diskStatsErr  map[string]error
	ioStats       map[string]disk.IOCountersStat
	ioStatsErr    error
}

func (m *mockDiskClient) Partitions(all bool) ([]disk.PartitionStat, error) {
	return m.partitions, m.partitionsErr
}

func (m *mockDiskClient) GetDiskStats(path string) (*disk.UsageStat, error) {
	if m.diskStatsErr != nil {
		if err, exists := m.diskStatsErr[path]; exists {
			return nil, err
		}
	}
	if m.diskStatsMap != nil {
		if stats, exists := m.diskStatsMap[path]; exists {
			return stats, nil
		}
	}
	return nil, fmt.Errorf("no mock data configured for path: %s", path)
}

func (m *mockDiskClient) IOCounters() (map[string]disk.IOCountersStat, error) {
	return m.ioStats, m.ioStatsErr
}

func TestBuildFilesystemMetrics_BasicCases(t *testing.T) {
	testCases := []struct {
		name           string
		kubeClient     kubepb.KubeAPIClient
		diskClient     DiskInterface
		expectError    bool
		errorContains  string
		validateMetric func(t *testing.T, metrics []FilesystemMetric, timestamp time.Time)
	}{
		{
			name: "success",
			kubeClient: &mockKubeClient{
				nodeTemplate: lo.ToPtr("test-template"),
			},
			diskClient: &mockDiskClient{
				partitions: []disk.PartitionStat{
					{
						Device: "/dev/sda1", Mountpoint: "/",
					},
				},
				diskStatsMap: map[string]*disk.UsageStat{
					hostPathRoot + "/": {
						Total: 1000000,
						Used:  500000,
					},
				},
			},
			validateMetric: func(t *testing.T, metrics []FilesystemMetric, timestamp time.Time) {
				require.Len(t, metrics, 1)
				metric := metrics[0]
				assert.Equal(t, "test-node", metric.NodeName)
				assert.Equal(t, "/", metric.MountPoint)
				assert.Equal(t, timestamp, metric.Timestamp)
				assert.Equal(t, []string{"/dev/sda1"}, metric.Devices)

				require.NotNil(t, metric.NodeTemplate)
				assert.Equal(t, "test-template", *metric.NodeTemplate)

				require.NotNil(t, metric.TotalSize)
				assert.Equal(t, int64(1000000), *metric.TotalSize)

				require.NotNil(t, metric.UsedSpace)
				assert.Equal(t, int64(500000), *metric.UsedSpace)
			},
		},
		{
			name:       "partition error",
			kubeClient: &mockKubeClient{nodeTemplate: lo.ToPtr("test-template")},
			diskClient: &mockDiskClient{
				partitionsErr: assert.AnError,
			},
			expectError:   true,
			errorContains: "failed to get partitions",
		},
		{
			name:       "missing node template",
			kubeClient: &mockKubeClient{nodeTemplate: nil},
			diskClient: &mockDiskClient{
				partitions: []disk.PartitionStat{
					{Device: "/dev/sda1", Mountpoint: "/"},
				},
				diskStatsMap: map[string]*disk.UsageStat{
					hostPathRoot + "/": {Total: 1000, Used: 500},
				},
			},
			validateMetric: func(t *testing.T, metrics []FilesystemMetric, timestamp time.Time) {
				require.Len(t, metrics, 1)
				assert.Nil(t, metrics[0].NodeTemplate)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := &SysfsStorageInfoProvider{
				log:          logging.NewTestLog(),
				diskClient:   tc.diskClient,
				nodeName:     "test-node",
				hostRootPath: "/proc/1/root",
				kubeClient:   tc.kubeClient,
				storageState: &storageMetricsState{
					blockDevices: make(map[string]*BlockDeviceMetric),
				},
			}

			timestamp := time.Now()
			metrics, err := provider.BuildFilesystemMetrics(timestamp)

			if tc.expectError {
				require.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
				return
			}

			require.NoError(t, err)
			if tc.validateMetric != nil {
				tc.validateMetric(t, metrics, timestamp)
			}
		})
	}
}

func TestBuildFilesystemMetrics_MissingDiskStats(t *testing.T) {
	mockDisk := &mockDiskClient{
		partitions: []disk.PartitionStat{
			{
				Device:     "/dev/sda1",
				Mountpoint: "/",
				Fstype:     "ext4",
			},
			{
				Device:     "/dev/sda1",
				Mountpoint: "/home",
				Fstype:     "ext4",
			},
		},
		diskStatsMap: map[string]*disk.UsageStat{
			hostPathRoot + "/": {
				Total: 1000000,
				Used:  500000,
			},
		},
		diskStatsErr: map[string]error{
			hostPathRoot + "/home": fmt.Errorf("internal error"),
		},
	}

	mockKube := &mockKubeClient{
		nodeTemplate: lo.ToPtr("test-template"),
	}

	provider := &SysfsStorageInfoProvider{
		log:          logging.NewTestLog(),
		diskClient:   mockDisk,
		nodeName:     "test-node",
		hostRootPath: "/proc/1/root",
		kubeClient:   mockKube,
	}

	timestamp := time.Now()
	metrics, err := provider.BuildFilesystemMetrics(timestamp)

	require.NoError(t, err)
	require.Len(t, metrics, 2)

	// First partition "/" should have disk stats (from mock GetDiskStats switch case)
	rootMetric := metrics[0]
	assert.Equal(t, "test-node", rootMetric.NodeName)
	assert.Equal(t, "/", rootMetric.MountPoint)
	assert.Equal(t, timestamp, rootMetric.Timestamp)
	assert.Equal(t, []string{"/dev/sda1"}, rootMetric.Devices)

	require.NotNil(t, rootMetric.NodeTemplate)
	assert.Equal(t, "test-template", *rootMetric.NodeTemplate)

	require.NotNil(t, rootMetric.TotalSize)
	assert.Equal(t, int64(1000000), *rootMetric.TotalSize)

	require.NotNil(t, rootMetric.UsedSpace)
	assert.Equal(t, int64(500000), *rootMetric.UsedSpace)

	// Second partition "/home" should have nil disk stats due to error in mock
	homeMetric := metrics[1]
	assert.Equal(t, "test-node", homeMetric.NodeName)
	assert.Equal(t, "/home", homeMetric.MountPoint)
	assert.Equal(t, timestamp, homeMetric.Timestamp)
	assert.Equal(t, []string{"/dev/sda1"}, homeMetric.Devices)

	require.NotNil(t, homeMetric.NodeTemplate)
	assert.Equal(t, "test-template", *homeMetric.NodeTemplate)

	assert.Nil(t, homeMetric.TotalSize)
	assert.Nil(t, homeMetric.UsedSpace)
}

func TestBuildBlockDeviceMetrics_BasicCases(t *testing.T) {
	testCases := []struct {
		name            string
		kubeClient      kubepb.KubeAPIClient
		diskClient      DiskInterface
		setupSecondCall func() DiskInterface
		expectError     bool
		errorContains   string
		validateMetric  func(t *testing.T, metric BlockDeviceMetric)
	}{
		{
			name: "rate calculation",
			kubeClient: &mockKubeClient{
				nodeTemplate: lo.ToPtr("test-template"),
			},
			diskClient: &mockDiskClient{
				ioStats: map[string]disk.IOCountersStat{
					"sda": {
						ReadCount:  100,
						WriteCount: 50,
						ReadBytes:  1000000,
						WriteBytes: 500000,
					},
				},
			},
			setupSecondCall: func() DiskInterface {
				return &mockDiskClient{
					ioStats: map[string]disk.IOCountersStat{
						"sda": {
							ReadCount:  200,     // +100 operations
							WriteCount: 100,     // +50 operations
							ReadBytes:  3000000, // +2000000 bytes
							WriteBytes: 1500000, // +1000000 bytes
						},
					},
				}
			},
			validateMetric: func(t *testing.T, metric BlockDeviceMetric) {
				assert.Equal(t, "sda", metric.Name)
				assert.Equal(t, "test-node", metric.NodeName)
				// Verify rate calculations: delta / time_diff (10 seconds)
				assert.Equal(t, int64(10), metric.ReadIOPS)            // (200-100)/10
				assert.Equal(t, int64(5), metric.WriteIOPS)            // (100-50)/10
				assert.Equal(t, int64(200000), metric.ReadThroughput)  // (3000000-1000000)/10
				assert.Equal(t, int64(100000), metric.WriteThroughput) // (1500000-500000)/10
			},
		},
		{
			name:       "io counters error",
			kubeClient: &mockKubeClient{nodeTemplate: lo.ToPtr("test-template")},
			diskClient: &mockDiskClient{
				ioStatsErr: fmt.Errorf("failed to read /proc/diskstats"),
			},
			expectError:   true,
			errorContains: "failed to get IO counters",
		},
		{
			name:       "node template error",
			kubeClient: nil, // nil client causes error
			diskClient: &mockDiskClient{
				ioStats: map[string]disk.IOCountersStat{
					"sda": {
						ReadCount:  100,
						WriteCount: 50,
						ReadBytes:  1000000,
						WriteBytes: 500000,
					},
				},
			},
			setupSecondCall: func() DiskInterface {
				return &mockDiskClient{
					ioStats: map[string]disk.IOCountersStat{
						"sda": {
							ReadCount:  200,
							WriteCount: 100,
							ReadBytes:  3000000,
							WriteBytes: 1500000,
						},
					},
				}
			},
			validateMetric: func(t *testing.T, metric BlockDeviceMetric) {
				assert.Equal(t, "sda", metric.Name)
				assert.Nil(t, metric.NodeTemplate) // Should be nil due to error
			},
		},
		{
			name: "counter reset detection",
			kubeClient: &mockKubeClient{
				nodeTemplate: lo.ToPtr("test-template"),
			},
			diskClient: &mockDiskClient{
				ioStats: map[string]disk.IOCountersStat{
					"sda": {
						ReadCount:  1000,
						WriteCount: 500,
						ReadBytes:  10000000,
						WriteBytes: 5000000,
					},
				},
			},
			setupSecondCall: func() DiskInterface {
				return &mockDiskClient{
					ioStats: map[string]disk.IOCountersStat{
						"sda": {
							// Counters reset to lower values (e.g., system reboot)
							ReadCount:  100,
							WriteCount: 50,
							ReadBytes:  1000000,
							WriteBytes: 500000,
						},
					},
				}
			},
			validateMetric: func(t *testing.T, metric BlockDeviceMetric) {
				assert.Equal(t, "sda", metric.Name)
				// When counter reset is detected, rates should be 0
				assert.Equal(t, int64(0), metric.ReadIOPS)
				assert.Equal(t, int64(0), metric.WriteIOPS)
				assert.Equal(t, int64(0), metric.ReadThroughput)
				assert.Equal(t, int64(0), metric.WriteThroughput)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := &SysfsStorageInfoProvider{
				log:        logging.NewTestLog(),
				diskClient: tc.diskClient,
				nodeName:   "test-node",
				kubeClient: tc.kubeClient,
				storageState: &storageMetricsState{
					blockDevices: make(map[string]*BlockDeviceMetric),
				},
			}

			firstTimestamp := time.Now()

			// First call
			firstMetrics, err := provider.BuildBlockDeviceMetrics(firstTimestamp)

			if tc.expectError {
				require.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
				return
			}

			require.NoError(t, err)
			require.Empty(t, firstMetrics) // First call always returns empty

			// Second call
			if tc.setupSecondCall != nil {
				secondTimestamp := firstTimestamp.Add(10 * time.Second)
				provider.diskClient = tc.setupSecondCall()

				secondMetrics, err := provider.BuildBlockDeviceMetrics(secondTimestamp)
				require.NoError(t, err)
				require.Len(t, secondMetrics, 1)

				if tc.validateMetric != nil {
					tc.validateMetric(t, secondMetrics[0])
				}
			}
		})
	}
}

func TestBuildBlockDeviceMetrics_DeviceSize_Cases(t *testing.T) {
	testCases := []struct {
		name           string
		sysBlockPrefix string
		setupFunc      func(string) error
		deviceName     string
		expectedSize   *int64
	}{
		{
			name:           "block device size available",
			sysBlockPrefix: "/tmp/test-sys-block",
			deviceName:     "sda",
			expectedSize:   lo.ToPtr(int64(1000 * 512)),
			setupFunc: func(prefix string) error {
				path := filepath.Join(prefix, "sys", "block", "sda", "size")
				if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
					return err
				}
				return os.WriteFile(path, []byte("1000\n"), 0644)
			},
		},
		{
			name:           "partition fallback",
			sysBlockPrefix: "/tmp/test-sys-partition",
			deviceName:     "sda1",
			expectedSize:   lo.ToPtr(int64(2000 * 512)),
			setupFunc: func(prefix string) error {
				path := filepath.Join(prefix, "sys", "block", "sda", "sda1", "size")
				if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
					return err
				}
				return os.WriteFile(path, []byte("2000\n"), 0644)
			},
		},
		{
			name:           "no size available",
			sysBlockPrefix: "/tmp/test-sys-nosize",
			deviceName:     "virt-device",
			expectedSize:   nil,
			setupFunc: func(prefix string) error {
				return os.MkdirAll(filepath.Join(prefix, "sys", "block"), 0755)
			},
		},
		{
			name:           "invalid sector data",
			sysBlockPrefix: "/tmp/test-sys-invalid",
			deviceName:     "sdb",
			expectedSize:   nil,
			setupFunc: func(prefix string) error {
				path := filepath.Join(prefix, "sys", "block", "sdb", "size")
				if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
					return err
				}
				return os.WriteFile(path, []byte("not-a-number\n"), 0644)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockKube := &mockKubeClient{
				nodeTemplate: lo.ToPtr("test-template"),
			}

			provider := &SysfsStorageInfoProvider{
				log:            logging.NewTestLog(),
				nodeName:       "test-node",
				kubeClient:     mockKube,
				sysBlockPrefix: tc.sysBlockPrefix,
				storageState: &storageMetricsState{
					blockDevices: make(map[string]*BlockDeviceMetric),
				},
			}

			// Setup test filesystem
			err := tc.setupFunc(tc.sysBlockPrefix)
			require.NoError(t, err)
			defer os.RemoveAll(tc.sysBlockPrefix)

			provider.diskClient = &mockDiskClient{
				ioStats: map[string]disk.IOCountersStat{
					tc.deviceName: {
						ReadCount:  100,
						WriteCount: 50,
						ReadBytes:  1000000,
						WriteBytes: 500000,
					},
				},
			}

			firstTimestamp := time.Now()
			secondTimestamp := firstTimestamp.Add(10 * time.Second)

			// First call - stores data but returns empty
			firstMetrics, err := provider.BuildBlockDeviceMetrics(firstTimestamp)
			require.NoError(t, err)
			require.Empty(t, firstMetrics)

			// Second call - returns metrics with size
			secondMetrics, err := provider.BuildBlockDeviceMetrics(secondTimestamp)
			require.NoError(t, err)
			require.Len(t, secondMetrics, 1)

			metric := secondMetrics[0]
			if tc.expectedSize == nil {
				assert.Nil(t, metric.Size)
			} else {
				require.NotNil(t, metric.Size)
				assert.Equal(t, *tc.expectedSize, *metric.Size)
			}
		})
	}
}

func TestBuildBlockDeviceMetrics_PhysicalDevicesResolution_Cases(t *testing.T) {
	testCases := []struct {
		name              string
		sysBlockPrefix    string
		hostRootPath      string
		setupFunc         func(string, string) error
		deviceName        string
		expectedPhysicals []string
	}{
		{
			name:              "simple device no slaves",
			sysBlockPrefix:    "/tmp/test-sys-simple",
			hostRootPath:      "/tmp/test-host-simple",
			deviceName:        "sda",
			expectedPhysicals: []string{"/dev/sda"},
			setupFunc: func(sysPrefix, hostPrefix string) error {
				slavesPath := filepath.Join(sysPrefix, "sys", "block", "sda", "slaves")
				return os.MkdirAll(slavesPath, 0755)
			},
		},
		{
			name:              "simple dm device",
			sysBlockPrefix:    "/tmp/test-sys-dm",
			hostRootPath:      "/tmp/test-host-dm",
			deviceName:        "dm-1",
			expectedPhysicals: []string{"/dev/dm-1"},
			setupFunc: func(sysPrefix, hostPrefix string) error {
				// Create empty slaves directory for dm device
				slavesPath := filepath.Join(sysPrefix, "sys", "block", "dm-1", "slaves")
				return os.MkdirAll(slavesPath, 0755)
			},
		},
		{
			name:              "device with slaves",
			sysBlockPrefix:    "/tmp/test-sys-slaves",
			hostRootPath:      "/tmp/test-host-slaves",
			deviceName:        "md0",
			expectedPhysicals: []string{"/dev/sda", "/dev/sdb"},
			setupFunc: func(sysPrefix, hostPrefix string) error {
				// Create RAID device with two slaves
				slavesPath := filepath.Join(sysPrefix, "sys", "block", "md0", "slaves")
				if err := os.MkdirAll(slavesPath, 0755); err != nil {
					return err
				}
				// Create slave symlinks
				if err := os.Symlink("../../sda", filepath.Join(slavesPath, "sda")); err != nil {
					return err
				}
				if err := os.Symlink("../../sdb", filepath.Join(slavesPath, "sdb")); err != nil {
					return err
				}

				// Create empty slaves for physical devices
				if err := os.MkdirAll(filepath.Join(sysPrefix, "sys", "block", "sda", "slaves"), 0755); err != nil {
					return err
				}
				return os.MkdirAll(filepath.Join(sysPrefix, "sys", "block", "sdb", "slaves"), 0755)
			},
		},
		{
			name:              "virtual device - slaves directory missing",
			sysBlockPrefix:    "/tmp/test-sys-missing",
			hostRootPath:      "/tmp/test-host-missing",
			deviceName:        "loop0",
			expectedPhysicals: []string{"/dev/loop0"},
			setupFunc: func(sysPrefix, hostPrefix string) error {
				return os.MkdirAll(filepath.Join(sysPrefix, "sys", "block"), 0755)
			},
		},
		{
			name:              "circular dependency detection",
			sysBlockPrefix:    "/tmp/test-sys-circular",
			hostRootPath:      "/tmp/test-host-circular",
			deviceName:        "md0",
			expectedPhysicals: []string{"/dev/md0"},
			setupFunc: func(sysPrefix, hostPrefix string) error {
				// Create circular dependency: md0 → sda → md0
				md0SlavesPath := filepath.Join(sysPrefix, "sys", "block", "md0", "slaves")
				sdaSlavesPath := filepath.Join(sysPrefix, "sys", "block", "sda", "slaves")

				if err := os.MkdirAll(md0SlavesPath, 0755); err != nil {
					return err
				}
				if err := os.MkdirAll(sdaSlavesPath, 0755); err != nil {
					return err
				}

				// md0 → sda
				if err := os.Symlink("../../sda", filepath.Join(md0SlavesPath, "sda")); err != nil {
					return err
				}
				// sda → md0 (creates circular dependency)
				return os.Symlink("../../md0", filepath.Join(sdaSlavesPath, "md0"))
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockKube := &mockKubeClient{
				nodeTemplate: lo.ToPtr("test-template"),
			}

			provider := &SysfsStorageInfoProvider{
				log:            logging.NewTestLog(),
				nodeName:       "test-node",
				kubeClient:     mockKube,
				sysBlockPrefix: tc.sysBlockPrefix,
				hostRootPath:   tc.hostRootPath,
				storageState: &storageMetricsState{
					blockDevices: make(map[string]*BlockDeviceMetric),
				},
			}

			// Setup test filesystem
			err := tc.setupFunc(tc.sysBlockPrefix, tc.hostRootPath)
			require.NoError(t, err)
			defer os.RemoveAll(tc.sysBlockPrefix)
			defer os.RemoveAll(tc.hostRootPath)

			provider.diskClient = &mockDiskClient{
				ioStats: map[string]disk.IOCountersStat{
					tc.deviceName: {
						ReadCount:  100,
						WriteCount: 50,
						ReadBytes:  1000000,
						WriteBytes: 500000,
					},
				},
			}

			firstTimestamp := time.Now()
			secondTimestamp := firstTimestamp.Add(10 * time.Second)

			// First call
			firstMetrics, err := provider.BuildBlockDeviceMetrics(firstTimestamp)
			require.NoError(t, err)
			require.Empty(t, firstMetrics)

			// Second call
			secondMetrics, err := provider.BuildBlockDeviceMetrics(secondTimestamp)
			require.NoError(t, err)
			require.Len(t, secondMetrics, 1)

			metric := secondMetrics[0]
			assert.Equal(t, tc.expectedPhysicals, metric.PhysicalDevices)
		})
	}
}

func TestBuildFilesystemMetrics_BackingDevicesResolution_Cases(t *testing.T) {
	testCases := []struct {
		name            string
		hostRootPath    string
		setupFunc       func(string) error
		devicePath      string
		mountPoint      string
		expectedDevices []string
	}{
		{
			name:            "regular device passthrough",
			hostRootPath:    "/tmp/test-host-regular",
			devicePath:      "/dev/sda1",
			mountPoint:      "/boot",
			expectedDevices: []string{"/dev/sda1"},
			setupFunc: func(hostPrefix string) error {
				return os.MkdirAll(hostPrefix, 0755)
			},
		},
		{
			name:            "lvm symlink resolution",
			hostRootPath:    "/tmp/test-host-lvm",
			devicePath:      "/dev/mapper/vg-lv",
			mountPoint:      "/home",
			expectedDevices: []string{"/dev/dm-1"},
			setupFunc: func(hostPrefix string) error {
				mapperDir := filepath.Join(hostPrefix, "dev", "mapper")
				if err := os.MkdirAll(mapperDir, 0755); err != nil {
					return err
				}
				return os.Symlink("../dm-1", filepath.Join(mapperDir, "vg-lv"))
			},
		},
		{
			name:            "lvm symlink broken fallback",
			hostRootPath:    "/tmp/test-host-broken",
			devicePath:      "/dev/mapper/broken-lv",
			mountPoint:      "/var",
			expectedDevices: []string{"/dev/mapper/broken-lv"},
			setupFunc: func(hostPrefix string) error {
				// Create mapper dir but no symlink (broken LVM)
				mapperDir := filepath.Join(hostPrefix, "dev", "mapper")
				return os.MkdirAll(mapperDir, 0755)
			},
		},
		{
			name:            "non-mapper device with mapper prefix",
			hostRootPath:    "/tmp/test-host-nonmapper",
			devicePath:      "/dev/disk/by-uuid/12345",
			mountPoint:      "/data",
			expectedDevices: []string{"/dev/disk/by-uuid/12345"},
			setupFunc: func(hostPrefix string) error {
				return os.MkdirAll(hostPrefix, 0755)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockKube := &mockKubeClient{
				nodeTemplate: lo.ToPtr("test-template"),
			}

			provider := &SysfsStorageInfoProvider{
				log:          logging.NewTestLog(),
				diskClient:   &mockDiskClient{},
				nodeName:     "test-node",
				hostRootPath: tc.hostRootPath,
				kubeClient:   mockKube,
			}

			err := tc.setupFunc(tc.hostRootPath)
			require.NoError(t, err)
			defer os.RemoveAll(tc.hostRootPath)

			provider.diskClient = &mockDiskClient{
				partitions: []disk.PartitionStat{
					{
						Device:     tc.devicePath,
						Mountpoint: tc.mountPoint,
						Fstype:     "ext4",
					},
				},
				diskStatsMap: map[string]*disk.UsageStat{
					tc.hostRootPath + tc.mountPoint: {Total: 2000000, Used: 1000000},
				},
			}

			metrics, err := provider.BuildFilesystemMetrics(time.Now())
			require.NoError(t, err)
			require.Len(t, metrics, 1)

			metric := metrics[0]
			assert.Equal(t, "test-node", metric.NodeName)
			assert.Equal(t, tc.mountPoint, metric.MountPoint)

			assert.Equal(t, tc.expectedDevices, metric.Devices)

			require.NotNil(t, metric.TotalSize)
			assert.Equal(t, int64(2000000), *metric.TotalSize)
		})
	}
}

func TestBuildBlockDeviceMetrics_MultipleDevices(t *testing.T) {
	mockKube := &mockKubeClient{
		nodeTemplate: lo.ToPtr("test-template"),
	}

	provider := &SysfsStorageInfoProvider{
		log:        logging.NewTestLog(),
		nodeName:   "test-node",
		kubeClient: mockKube,
		storageState: &storageMetricsState{
			blockDevices: make(map[string]*BlockDeviceMetric),
		},
	}

	provider.diskClient = &mockDiskClient{
		ioStats: map[string]disk.IOCountersStat{
			"sda": {
				ReadCount:  100,
				WriteCount: 50,
				ReadBytes:  1000000,
				WriteBytes: 500000,
			},
			"sdb": {
				ReadCount:  200,
				WriteCount: 100,
				ReadBytes:  2000000,
				WriteBytes: 1000000,
			},
			"nvme0n1": {
				ReadCount:  300,
				WriteCount: 150,
				ReadBytes:  3000000,
				WriteBytes: 1500000,
			},
		},
	}

	firstTimestamp := time.Now()
	secondTimestamp := firstTimestamp.Add(10 * time.Second)

	// First call
	firstMetrics, err := provider.BuildBlockDeviceMetrics(firstTimestamp)
	require.NoError(t, err)
	require.Empty(t, firstMetrics)

	// Update counters for second call
	provider.diskClient = &mockDiskClient{
		ioStats: map[string]disk.IOCountersStat{
			"sda": {
				ReadCount:  200,     // +100
				WriteCount: 100,     // +50
				ReadBytes:  3000000, // +2000000
				WriteBytes: 1500000, // +1000000
			},
			"sdb": {
				ReadCount:  400,     // +200
				WriteCount: 200,     // +100
				ReadBytes:  6000000, // +4000000
				WriteBytes: 3000000, // +2000000
			},
			"nvme0n1": {
				ReadCount:  450,     // +150
				WriteCount: 225,     // +75
				ReadBytes:  6000000, // +3000000
				WriteBytes: 3000000, // +1500000
			},
		},
	}

	// Second call
	secondMetrics, err := provider.BuildBlockDeviceMetrics(secondTimestamp)
	require.NoError(t, err)
	require.Len(t, secondMetrics, 3)

	metricsByName := make(map[string]BlockDeviceMetric)
	for _, metric := range secondMetrics {
		metricsByName[metric.Name] = metric
	}

	sdaMetric := metricsByName["sda"]
	assert.Equal(t, int64(10), sdaMetric.ReadIOPS)            // (200-100)/10
	assert.Equal(t, int64(5), sdaMetric.WriteIOPS)            // (100-50)/10
	assert.Equal(t, int64(200000), sdaMetric.ReadThroughput)  // (3000000-1000000)/10
	assert.Equal(t, int64(100000), sdaMetric.WriteThroughput) // (1500000-500000)/10

	sdbMetric := metricsByName["sdb"]
	assert.Equal(t, int64(20), sdbMetric.ReadIOPS)            // (400-200)/10
	assert.Equal(t, int64(10), sdbMetric.WriteIOPS)           // (200-100)/10
	assert.Equal(t, int64(400000), sdbMetric.ReadThroughput)  // (6000000-2000000)/10
	assert.Equal(t, int64(200000), sdbMetric.WriteThroughput) // (3000000-1000000)/10

	nvmeMetric := metricsByName["nvme0n1"]
	assert.Equal(t, int64(15), nvmeMetric.ReadIOPS)            // (450-300)/10
	assert.Equal(t, int64(7), nvmeMetric.WriteIOPS)            // (225-150)/10 = 7.5 → 7
	assert.Equal(t, int64(300000), nvmeMetric.ReadThroughput)  // (6000000-3000000)/10
	assert.Equal(t, int64(150000), nvmeMetric.WriteThroughput) // (3000000-1500000)/10
}

func TestSafeDelta(t *testing.T) {
	testCases := []struct {
		name     string
		current  uint64
		previous uint64
		expected int64
	}{
		{
			name:     "normal increment",
			current:  100,
			previous: 50,
			expected: 50,
		},
		{
			name:     "no change",
			current:  100,
			previous: 100,
			expected: 0,
		},
		{
			name:     "counter reset detected",
			current:  50,
			previous: 100,
			expected: 0,
		},
		{
			name:     "zero to value",
			current:  100,
			previous: 0,
			expected: 100,
		},
		{
			name:     "value to zero (reset)",
			current:  0,
			previous: 100,
			expected: 0,
		},
		{
			name:     "large delta within int64 range",
			current:  uint64(math.MaxInt64),
			previous: 1000,
			expected: math.MaxInt64 - 1000,
		},
		{
			name:     "delta exactly at MaxInt64",
			current:  uint64(math.MaxInt64) + 1000,
			previous: 1000,
			expected: math.MaxInt64,
		},
		{
			name:     "delta exceeding MaxInt64 gets clamped",
			current:  math.MaxUint64,
			previous: 1000,
			expected: math.MaxInt64,
		},
		{
			name:     "large values no overflow",
			current:  math.MaxUint64 - 1000,
			previous: math.MaxUint64 - 2000,
			expected: 1000,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := safeDelta(tc.current, tc.previous)
			assert.Equal(t, tc.expected, result)
		})
	}
}
