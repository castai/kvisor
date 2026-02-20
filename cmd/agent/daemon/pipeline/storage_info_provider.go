package pipeline

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/elastic/go-freelru"
	"github.com/samber/lo"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding/gzip"

	kubepb "github.com/castai/kvisor/api/v1/kube"
	"github.com/castai/kvisor/cmd/agent/daemon/config"
	"github.com/castai/kvisor/pkg/cloudprovider/types"
	"github.com/castai/logging"
)

const sectorSizeBytes = 512
const hostPathRoot = "/proc/1/root"

// BlockDeviceMetric represents enhanced block device metrics with accurate sector sizes
type BlockDeviceMetric struct {
	Name         string            `avro:"name"`
	NodeName     string            `avro:"node_name"`
	NodeTemplate *string           `avro:"node_template"`
	Path         string            `avro:"path"`
	SizeBytes    *int64            `avro:"size_bytes"`
	DiskType     string            `avro:"disk_type"`    // HDD, SSD
	PartitionOf  string            `avro:"partition_of"` // parent device for partitions
	Holders      []string          `avro:"holders"`      // devices using this device
	IsVirtual    bool              `avro:"is_virtual"`   // dm-* or md* devices
	RaidLevel    string            `avro:"raid_level"`   // raid0, raid1, raid5, etc
	LVMInfo      map[string]string `avro:"lvm_info"`     // LVM metadata for this device

	CloudVolumeID string `avro:"volume_id"` // ID of the correlating CSP disk

	ReadIOPS             float64   `avro:"read_iops"`
	WriteIOPS            float64   `avro:"write_iops"`
	ReadThroughputBytes  float64   `avro:"read_throughput_bytes"`
	WriteThroughputBytes float64   `avro:"write_throughput_bytes"`
	ReadLatencyMs        float64   `avro:"read_latency_ms"`
	WriteLatencyMs       float64   `avro:"write_latency_ms"`
	InFlightRequests     int64     `avro:"in_flight_requests"`
	AvgQueueDepth        float64   `avro:"avg_queue_depth"`
	Utilization          float64   `avro:"utilization"`
	Timestamp            time.Time `avro:"ts"`

	// Internal fields for calculation (raw cumulative counters)
	logicalSectorSize uint64
	readIOs           uint64
	writeIOs          uint64
	readSectors       uint64
	writeSectors      uint64
	readTicks         uint64
	writeTicks        uint64
	ioTicks           uint64
	timeInQueue       uint64
}

type FilesystemMetric struct {
	Devices      []string          `avro:"devices"`
	NodeName     string            `avro:"node_name"`
	NodeTemplate *string           `avro:"node_template"`
	MountPoint   string            `avro:"mount_point"`
	Type         string            `avro:"type"`    // Filesystem type (ext4, xfs, btrfs, etc.)
	Options      []string          `avro:"options"` // Mount options
	TotalBytes   *int64            `avro:"total_bytes"`
	Labels       map[string]string `avro:"labels"`
	UsedBytes    *int64            `avro:"used_bytes"`
	TotalInodes  *int64            `avro:"total_inodes"`
	UsedInodes   *int64            `avro:"used_inodes"`
	Timestamp    time.Time         `avro:"ts"`

	// PV name for joining with K8sPodVolumeMetric (nil for node-level filesystems)
	PVName *string `avro:"pv_name"`
}

// NodeStatsSummaryMetric represents node-level filesystem statistics from kubelet
type NodeStatsSummaryMetric struct {
	NodeName                  string    `avro:"node_name"`
	NodeTemplate              *string   `avro:"node_template"`
	ImageFsSizeBytes          *int64    `avro:"image_fs_size_bytes"`
	ImageFsUsedBytes          *int64    `avro:"image_fs_used_bytes"`
	ContainerFsSizeBytes      *int64    `avro:"container_fs_size_bytes"`
	ContainerFsUsedBytes      *int64    `avro:"container_fs_used_bytes"`
	EphemeralStorageSizeBytes *uint64   `avro:"ephemeral_storage_size_bytes"`
	EphemeralStorageUsedBytes *uint64   `avro:"ephemeral_storage_used_bytes"`
	Timestamp                 time.Time `avro:"ts"`
}

// K8sPodVolumeMetric represents pod volume information from Kubernetes
type K8sPodVolumeMetric struct {
	NodeName           string    `avro:"node_name"`
	NodeTemplate       *string   `avro:"node_template"`
	Namespace          string    `avro:"namespace"`
	PodName            string    `avro:"pod_name"`
	PodUID             string    `avro:"pod_uid"`
	ControllerKind     string    `avro:"controller_kind"`
	ControllerName     string    `avro:"controller_name"`
	ContainerName      string    `avro:"container_name"`
	VolumeName         string    `avro:"volume_name"`
	MountPath          string    `avro:"mount_path"`
	PVCName            *string   `avro:"pvc_name"`
	RequestedSizeBytes *int64    `avro:"requested_size_bytes"`
	PVName             *string   `avro:"pv_name"`
	StorageClass       *string   `avro:"storage_class"`
	CSIDriver          *string   `avro:"csi_driver"`
	CSIVolumeHandle    *string   `avro:"csi_volume_handle"` // For EBS: vol-xxx, can be joined with block_device.ebs_volume_id
	VolumeMode         string    `avro:"volume_mode"`       // "Filesystem" or "Block"
	DevicePath         *string   `avro:"device_path"`       // For block volumes: container's volumeDevices[].devicePath
	Timestamp          time.Time `avro:"ts"`
}

// CloudVolumeMetric represents cloud provider volume metadata and configuration
type CloudVolumeMetric struct {
	NodeName        string    `avro:"node_name"`
	NodeTemplate    *string   `avro:"node_template"`
	CloudProvider   string    `avro:"cloud_provider"`
	Zone            string    `avro:"zone"`
	VolumeID        string    `avro:"volume_id"`
	VolumeType      string    `avro:"volume_type"`
	VolumeState     string    `avro:"volume_state"`
	SizeBytes       int64     `avro:"size_bytes"`
	IOPS            int32     `avro:"iops"`
	ThroughputBytes int32     `avro:"throughput_bytes"`
	Encrypted       bool      `avro:"encrypted"`
	Timestamp       time.Time `avro:"ts"`
}

type storageMetricsState struct {
	blockDevices map[string]*BlockDeviceMetric
	filesystems  map[string]*FilesystemMetric
}

type StorageInfoProvider interface {
	CollectFilesystemMetrics(ctx context.Context, timestamp time.Time) ([]FilesystemMetric, error)
	CollectBlockDeviceMetrics(ctx context.Context, timestamp time.Time) ([]BlockDeviceMetric, error)
	CollectNodeStatsSummary(ctx context.Context, source config.EphemeralStorageSource) (*NodeStatsSummaryMetric, error)
	CollectPodVolumeMetrics(ctx context.Context) ([]K8sPodVolumeMetric, error)
	CollectCloudVolumeMetrics(ctx context.Context) ([]CloudVolumeMetric, error)
}

type cloudVolumeCache struct {
	mu               sync.Mutex
	cloudVolumesResp *kubepb.GetCloudVolumesResponse
	lastLoadTime     time.Time
}

type SysfsStorageInfoProvider struct {
	log                   *logging.Logger
	storageState          *storageMetricsState
	nodeName              string
	clusterID             string
	hostRootPath          string
	sysBlockPrefix        string
	kubeClient            kubepb.KubeAPIClient
	nodeCache             *freelru.SyncedLRU[string, *kubepb.Node]
	cloudVolumeCache      cloudVolumeCache
	wellKnownPathDeviceID map[string]uint64
}

const (
	kubeletPath       = "/var/lib/kubelet"
	containerdPath    = "/var/lib/containerd"
	crioPath          = "/var/lib/containers"
	castaiStoragePath = "/var/lib/castai-storage"
)

func NewStorageInfoProvider(log *logging.Logger, kubeClient kubepb.KubeAPIClient, clusterID string) (StorageInfoProvider, error) {
	nodeCache, err := freelru.NewSynced[string, *kubepb.Node](4, func(k string) uint32 {
		return uint32(xxhash.Sum64String(k)) // nolint:gosec
	})
	if err != nil {
		return nil, fmt.Errorf("nodeCache can not be initialized")
	}

	wellKnownPathDeviceID := make(map[string]uint64)

	kubeletResolvedPath := filepath.Join(hostPathRoot, kubeletPath)
	kubeletDeviceID, err := getDeviceIDForPath(kubeletResolvedPath)
	if err == nil {
		wellKnownPathDeviceID[kubeletPath] = kubeletDeviceID
	} else {
		log.With("path", kubeletResolvedPath).
			With("error", err).
			Warn("failed to stat kubelet path")
	}

	containerdResolvedPath := filepath.Join(hostPathRoot, containerdPath)
	containerdDeviceID, err := getDeviceIDForPath(containerdResolvedPath)
	if err == nil {
		wellKnownPathDeviceID[containerdPath] = containerdDeviceID
	} else {
		log.With("path", containerdResolvedPath).
			With("error", err).
			Warn("failed to stat containerd path")
	}

	crioResolvedPath := filepath.Join(hostPathRoot, crioPath)
	crioDeviceID, err := getDeviceIDForPath(crioResolvedPath)
	if err == nil {
		wellKnownPathDeviceID[crioPath] = crioDeviceID
	} else {
		log.With("path", crioResolvedPath).
			With("error", err).
			Warn("failed to stat crio path")
	}

	return &SysfsStorageInfoProvider{
		storageState: &storageMetricsState{
			blockDevices: make(map[string]*BlockDeviceMetric),
			filesystems:  make(map[string]*FilesystemMetric),
		},
		log:                   log,
		nodeName:              os.Getenv("NODE_NAME"),
		clusterID:             clusterID,
		hostRootPath:          hostPathRoot,
		sysBlockPrefix:        "",
		kubeClient:            kubeClient,
		nodeCache:             nodeCache,
		wellKnownPathDeviceID: wellKnownPathDeviceID,
	}, nil
}

func (s *SysfsStorageInfoProvider) getNode() (*kubepb.Node, error) {
	if s.kubeClient == nil {
		return nil, fmt.Errorf("kube client is not initialized")
	}

	if s.nodeCache != nil {
		node, found := s.nodeCache.Get(s.nodeName)
		if found {
			return node, nil
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := s.kubeClient.GetNode(ctx, &kubepb.GetNodeRequest{
		Name: s.nodeName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get node %s: %w", s.nodeName, err)
	}

	if resp.Node == nil {
		return nil, fmt.Errorf("failed to get node")
	}

	if s.nodeCache != nil {
		s.nodeCache.Add(s.nodeName, resp.Node)
	}

	return resp.Node, nil
}

func (s *SysfsStorageInfoProvider) getNodeTemplate() (*string, error) {
	node, err := s.getNode()
	if err != nil {
		return nil, err
	}

	if node.Labels == nil {
		return nil, nil
	}

	// Try the scheduling label first (current standard)
	if nodeTemplate, exists := node.Labels["scheduling.cast.ai/node-template"]; exists {
		return &nodeTemplate, nil
	}

	// Fallback to provisioner label (legacy)
	if nodeTemplate, exists := node.Labels["provisioner.cast.ai/node-template"]; exists {
		return &nodeTemplate, nil
	}

	return nil, nil
}

// CollectNodeStatsSummary retrieves node stats summary from the controller and builds a metric.
// The source parameter controls how ephemeral storage fields are populated; EphemeralStorageSourceNone
// leaves them nil.
func (s *SysfsStorageInfoProvider) CollectNodeStatsSummary(ctx context.Context, source config.EphemeralStorageSource) (*NodeStatsSummaryMetric, error) {
	if s.kubeClient == nil {
		return nil, fmt.Errorf("kube client is not initialized")
	}

	log := s.log.WithField("collector", "node_stats")

	// Get node stats summary from controller
	resp, err := s.kubeClient.GetNodeStatsSummary(ctx, &kubepb.GetNodeStatsSummaryRequest{
		NodeName: s.nodeName,
	}, grpc.UseCompressor(gzip.Name))
	if err != nil {
		return nil, fmt.Errorf("failed to get node stats summary for %s: %w", s.nodeName, err)
	}

	if resp == nil || resp.Node == nil {
		return nil, fmt.Errorf("empty node stats response for %s", s.nodeName)
	}

	// Get node template
	nodeTemplate, err := s.getNodeTemplate()
	if err != nil {
		log.Warnf("failed to get node template: %v", err)
		// Don't fail the whole collection if node template lookup fails
		nodeTemplate = nil
	}

	// Extract filesystem metrics
	metric := &NodeStatsSummaryMetric{
		NodeName:     s.nodeName,
		NodeTemplate: nodeTemplate,
		Timestamp:    time.Now(),
	}

	if resp.Node.Runtime != nil {
		if resp.Node.Runtime.ImageFs != nil {
			if resp.Node.Runtime.ImageFs.CapacityBytes > 0 {
				metric.ImageFsSizeBytes = lo.ToPtr(safeUint64ToInt64(resp.Node.Runtime.ImageFs.CapacityBytes))
			}
			if resp.Node.Runtime.ImageFs.UsedBytes > 0 {
				metric.ImageFsUsedBytes = lo.ToPtr(safeUint64ToInt64(resp.Node.Runtime.ImageFs.UsedBytes))
			}
		}
		if resp.Node.Runtime.ContainerFs != nil {
			if resp.Node.Runtime.ContainerFs.CapacityBytes > 0 {
				metric.ContainerFsSizeBytes = lo.ToPtr(safeUint64ToInt64(resp.Node.Runtime.ContainerFs.CapacityBytes))
			}
			if resp.Node.Runtime.ContainerFs.UsedBytes > 0 {
				metric.ContainerFsUsedBytes = lo.ToPtr(safeUint64ToInt64(resp.Node.Runtime.ContainerFs.UsedBytes))
			}
		}
	}

	switch source {
	case config.EphemeralStorageSourceKubelet:
		// node.fs represents the root filesystem where ephemeral storage resides.
		// This is the same data source kubelet uses when enforcing ephemeral-storage limits.
		if resp.Node.Fs != nil {
			if resp.Node.Fs.CapacityBytes > 0 {
				metric.EphemeralStorageSizeBytes = lo.ToPtr(resp.Node.Fs.CapacityBytes)
			}
			if resp.Node.Fs.UsedBytes > 0 {
				metric.EphemeralStorageUsedBytes = lo.ToPtr(resp.Node.Fs.UsedBytes)
			}
		}
	case config.EphemeralStorageSourceLocal:
		size, used, localErr := s.collectEphemeralStorageLocal()
		if localErr != nil {
			log.Warnf("failed to collect local ephemeral storage: %v", localErr)
		} else {
			if size > 0 {
				metric.EphemeralStorageSizeBytes = lo.ToPtr(size)
			}
			if used > 0 {
				metric.EphemeralStorageUsedBytes = lo.ToPtr(used)
			}
		}
		// EphemeralStorageSourceNone: leave fields nil.
	}

	return metric, nil
}

// collectEphemeralStorageLocal measures ephemeral storage by inspecting the host's
// mount table (/proc/1/mountinfo).  It finds all ext4/xfs mounts under
// /var/lib/kubelet, deduplicates them by device ID, and sums their statfs
// capacity and used bytes.  If no dedicated mount exists under /var/lib/kubelet
// the deepest mount whose point is a prefix of /var/lib/kubelet is used as a
// fallback (e.g. the root filesystem "/").
func (s *SysfsStorageInfoProvider) collectEphemeralStorageLocal() (sizeBytes, usedBytes uint64, err error) {
	mounts, err := readMountInfo("")
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read mount info: %w", err)
	}
	return s.collectEphemeralStorageLocalFromMounts(mounts)
}

// collectEphemeralStorageLocalFromMounts is the testable core of
// collectEphemeralStorageLocal; it accepts a pre-parsed mount list so tests
// can inject arbitrary mount tables without touching the filesystem.
func (s *SysfsStorageInfoProvider) collectEphemeralStorageLocalFromMounts(mounts []mountInfo) (sizeBytes, usedBytes uint64, err error) {
	// Collect mounts directly under /var/lib/kubelet (ext4 / xfs only).
	var kubeletMounts []mountInfo
	for _, m := range mounts {
		if !isEphemeralLocalFilesystem(m.FsType) {
			continue
		}
		if strings.HasPrefix(m.MountPoint, kubeletPath) {
			kubeletMounts = append(kubeletMounts, m)
		}
	}

	// Fallback: no dedicated mount found — find the deepest mount whose point
	// is a prefix of /var/lib/kubelet (e.g. "/" or "/var/lib").
	if len(kubeletMounts) == 0 {
		var best *mountInfo
		for i := range mounts {
			m := &mounts[i]
			if !isEphemeralLocalFilesystem(m.FsType) {
				continue
			}
			// The mount point must be a prefix of kubeletPath.
			prefix := m.MountPoint
			if prefix != "/" {
				prefix = prefix + "/"
			}
			if !strings.HasPrefix(kubeletPath+"/", prefix) {
				continue
			}
			// Prefer the deepest (longest) matching mount point.
			if best == nil || len(m.MountPoint) > len(best.MountPoint) {
				best = m
			}
		}
		if best != nil {
			kubeletMounts = []mountInfo{*best}
		}
	}

	if len(kubeletMounts) == 0 {
		return 0, 0, nil
	}

	// Deduplicate by device ID, then sum.
	seen := make(map[uint64]struct{}, len(kubeletMounts))
	for _, m := range kubeletMounts {
		hostPath := filepath.Join(s.hostRootPath, m.MountPoint)
		size, used, _, _, devID, statErr := getFilesystemStats(hostPath)
		if statErr != nil {
			s.log.Warnf("collectEphemeralStorageLocal: skipping %s: %v", m.MountPoint, statErr)
			continue
		}
		if _, alreadySeen := seen[devID]; alreadySeen {
			continue
		}
		seen[devID] = struct{}{}
		sizeBytes += safeInt64ToUint64(size)
		usedBytes += safeInt64ToUint64(used)
	}

	return sizeBytes, usedBytes, nil
}

// isEphemeralLocalFilesystem returns true for the filesystem types supported by
// the local ephemeral storage collector.
func isEphemeralLocalFilesystem(fsType string) bool {
	return fsType == "ext4" || fsType == "xfs"
}

// CollectPodVolumeMetrics retrieves pod volume information from the controller
func (s *SysfsStorageInfoProvider) CollectPodVolumeMetrics(ctx context.Context) ([]K8sPodVolumeMetric, error) {
	if s.kubeClient == nil {
		return nil, fmt.Errorf("kube client is not initialized")
	}

	log := s.log.WithField("collector", "pod_volumes")

	log.Debugf("requesting pod volumes for node %s", s.nodeName)
	resp, err := s.kubeClient.GetPodVolumes(ctx, &kubepb.GetPodVolumesRequest{
		NodeName: s.nodeName,
	}, grpc.UseCompressor(gzip.Name))
	if err != nil {
		return nil, fmt.Errorf("failed to get pod volumes for node %s: %w", s.nodeName, err)
	}

	if len(resp.Volumes) == 0 {
		return nil, nil
	}

	log.Debugf("received %d volumes from controller for node %s", len(resp.Volumes), s.nodeName)

	nodeTemplate, err := s.getNodeTemplate()
	if err != nil {
		log.Warnf("failed to get node template: %v", err)
		nodeTemplate = nil
	}

	timestamp := time.Now().UTC()
	metrics := make([]K8sPodVolumeMetric, len(resp.Volumes))

	for i, v := range resp.Volumes {
		metric := K8sPodVolumeMetric{
			NodeName:       s.nodeName,
			NodeTemplate:   nodeTemplate,
			Namespace:      v.Namespace,
			PodName:        v.PodName,
			PodUID:         v.PodUid,
			ControllerKind: v.ControllerKind,
			ControllerName: v.ControllerName,
			ContainerName:  v.ContainerName,
			VolumeName:     v.VolumeName,
			MountPath:      v.MountPath,
			VolumeMode:     v.VolumeMode,
			Timestamp:      timestamp,
		}

		if v.PvcName != "" {
			metric.PVCName = &v.PvcName
		}
		if v.RequestedSizeBytes > 0 {
			metric.RequestedSizeBytes = &v.RequestedSizeBytes
		}
		if v.PvName != "" {
			metric.PVName = &v.PvName
		}
		if v.StorageClass != "" {
			metric.StorageClass = &v.StorageClass
		}
		if v.CsiDriver != "" {
			metric.CSIDriver = &v.CsiDriver
		}
		if v.CsiVolumeHandle != "" {
			metric.CSIVolumeHandle = &v.CsiVolumeHandle
		}
		if v.DevicePath != "" {
			metric.DevicePath = &v.DevicePath
		}

		metrics[i] = metric
	}

	return metrics, nil
}

func (s *SysfsStorageInfoProvider) getNodeCloudVolumes(ctx context.Context) (*kubepb.GetCloudVolumesResponse, error) {
	s.cloudVolumeCache.mu.Lock()
	defer s.cloudVolumeCache.mu.Unlock()

	// HACK(patrick.pichler): This needs some refactoring. It works for now, but we need a better caching strategy.

	// TODO(patrick.pichler): Make cache lifetime configurable
	if s.cloudVolumeCache.cloudVolumesResp != nil && s.cloudVolumeCache.lastLoadTime.After(time.Now().Add(-30*time.Second)) {
		return s.cloudVolumeCache.cloudVolumesResp, nil
	}

	resp, err := s.kubeClient.GetCloudVolumes(ctx, &kubepb.GetCloudVolumesRequest{
		NodeName: s.nodeName,
	}, grpc.UseCompressor(gzip.Name))
	if err != nil {
		return nil, err
	}

	s.cloudVolumeCache.cloudVolumesResp = resp
	s.cloudVolumeCache.lastLoadTime = time.Now()

	return resp, nil
}

// CollectCloudVolumeMetrics retrieves cloud volume metadata from the cloud provider and builds metrics
func (s *SysfsStorageInfoProvider) CollectCloudVolumeMetrics(ctx context.Context) ([]CloudVolumeMetric, error) {
	if s.kubeClient == nil {
		return nil, fmt.Errorf("kube client is not initialized")
	}

	log := s.log.WithField("collector", "cloud_volumes")

	log.Debugf("requesting cloud volumes for node %s", s.nodeName)
	resp, err := s.getNodeCloudVolumes(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get cloud volumes for %s: %w", s.nodeName, err)
	}

	if len(resp.Volumes) == 0 {
		return nil, nil
	}

	log.Debugf("received %d cloud volumes from controller for node %s", len(resp.Volumes), s.nodeName)

	nodeTemplate, err := s.getNodeTemplate()
	if err != nil {
		log.Warnf("failed to get node template: %v", err)
		nodeTemplate = nil
	}

	timestamp := time.Now().UTC()
	metrics := make([]CloudVolumeMetric, len(resp.Volumes))

	for i, v := range resp.Volumes {
		metric := CloudVolumeMetric{
			NodeName:        s.nodeName,
			NodeTemplate:    nodeTemplate,
			CloudProvider:   v.CloudProvider,
			Zone:            v.Zone,
			VolumeID:        v.VolumeId,
			VolumeType:      v.VolumeType,
			VolumeState:     v.VolumeState,
			SizeBytes:       v.SizeBytes,
			IOPS:            v.Iops,
			ThroughputBytes: v.ThroughputBytes,
			Encrypted:       v.Encrypted,
			Timestamp:       timestamp,
		}
		metrics[i] = metric
	}

	return metrics, nil
}

func (s *SysfsStorageInfoProvider) CollectFilesystemMetrics(ctx context.Context, timestamp time.Time) ([]FilesystemMetric, error) {
	// Read mount information from /proc/1/mountinfo
	mounts, err := readMountInfo("/proc/1/mountinfo")
	if err != nil {
		return nil, fmt.Errorf("failed to read mountinfo: %w", err)
	}

	// Build pod volume lookup map for enrichment
	podVolumeMap := s.buildPodVolumeLookupMap(ctx)

	// Deduplicate by major:minor device ID
	// When multiple mounts point to the same device (bind mounts), prefer paths
	// matching /var/lib/kubelet/pods because they can be enriched with pod metadata
	seenDevices := make(map[string]FilesystemMetric)
	for _, mount := range mounts {
		metric, err := s.buildFilesystemMetric(mount, timestamp, podVolumeMap)
		if err != nil {
			s.log.Warnf("skipping filesystem metric for %s: %v", mount.MountPoint, err)
			continue
		}

		deviceKey := mount.MajorMinor
		if existing, seen := seenDevices[deviceKey]; seen {
			// Prefer the mount that has PV metadata (was enriched with K8s info)
			if metric.PVName != nil && existing.PVName == nil {
				seenDevices[deviceKey] = metric
			}
			// Otherwise keep the first one we saw
		} else {
			seenDevices[deviceKey] = metric
		}
	}

	filesystemMetrics := make([]FilesystemMetric, 0, len(seenDevices))
	for _, metric := range seenDevices {
		filesystemMetrics = append(filesystemMetrics, metric)
	}

	return filesystemMetrics, nil
}

// podVolumeKey generates a lookup key from pod UID and volume name
func podVolumeKey(podUID, volumeName string) string {
	return podUID + "/" + volumeName
}

// buildPodVolumeLookupMap fetches pod volumes from controller and builds a lookup map
// The map is keyed by both:
// - podUID/volumeName (for emptyDir, configMap, etc.)
// - podUID/pvName (for CSI volumes where the mount path contains the PV name)
func (s *SysfsStorageInfoProvider) buildPodVolumeLookupMap(ctx context.Context) map[string]*kubepb.PodVolumeInfo {
	if s.kubeClient == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	resp, err := s.kubeClient.GetPodVolumes(ctx, &kubepb.GetPodVolumesRequest{
		NodeName: s.nodeName,
	}, grpc.UseCompressor(gzip.Name))
	if err != nil {
		s.log.Warnf("failed to get pod volumes for enrichment: %v", err)
		return nil
	}

	volumeMap := make(map[string]*kubepb.PodVolumeInfo, len(resp.Volumes)*2)
	for _, v := range resp.Volumes {
		// Primary key: podUID/volumeName
		key := podVolumeKey(v.PodUid, v.VolumeName)
		volumeMap[key] = v

		// Secondary key: podUID/pvName (for CSI volumes)
		// CSI mount paths use the PV name as the directory name, not the volume name
		if v.PvName != "" {
			pvKey := podVolumeKey(v.PodUid, v.PvName)
			volumeMap[pvKey] = v
		}
	}

	return volumeMap
}

func (s *SysfsStorageInfoProvider) buildFilesystemMetric(mount mountInfo, timestamp time.Time, podVolumeMap map[string]*kubepb.PodVolumeInfo) (FilesystemMetric, error) {
	// Construct the path from host's root to access the filesystem
	fileSystemPath := filepath.Join(s.hostRootPath, mount.MountPoint)

	// Get filesystem statistics using syscall.Statfs
	sizeBytes, usedBytes, totalInodes, usedInodes, devID, statsErr := getFilesystemStats(fileSystemPath)
	if statsErr != nil {
		return FilesystemMetric{}, fmt.Errorf("failed to get filesystem stats for %s: %w", mount.MountPoint, statsErr)
	}

	nodeTemplate, err := s.getNodeTemplate()
	if err != nil {
		s.log.Warnf("failed to get node template for %s: %v", mount.MountPoint, err)
	}

	// Check whether the filesystem is holding kubelet and/or castai-storage directories
	labels := buildFilesystemLabels(s.log, devID, s.wellKnownPathDeviceID)

	metric := FilesystemMetric{
		Devices:      s.getBackingDevices(mount.Device),
		NodeName:     s.nodeName,
		NodeTemplate: nodeTemplate,
		MountPoint:   mount.MountPoint,
		Type:         mount.FsType,
		Options:      mount.Options,
		TotalBytes:   &sizeBytes,
		UsedBytes:    &usedBytes,
		TotalInodes:  &totalInodes,
		UsedInodes:   &usedInodes,
		Labels:       labels,
		Timestamp:    timestamp,
	}

	// Check if this is a pod volume mount and enrich with PV name for joining
	if volInfo := ParseVolumeMountPath(mount.MountPoint); volInfo != nil && podVolumeMap != nil {
		key := podVolumeKey(volInfo.PodUID, volInfo.VolumeName)
		if pv, ok := podVolumeMap[key]; ok && pv.PvName != "" {
			metric.PVName = &pv.PvName
		}
	}

	return metric, nil
}

// getBackingDevices resolves a device to its backing device.
// For LVM: "/dev/mapper/vg-lv" → "/dev/dm-1"
// For regular devices: "/dev/sda1" → "/dev/sda1"
func (s *SysfsStorageInfoProvider) getBackingDevices(device string) []string {
	if slaves := s.getLVMDMDevice(device); len(slaves) > 0 {
		return slaves
	}

	return []string{device}
}

// getLVMDMDevice resolves LVM logical volumes to their dm device.
// It handles the symlink chain: /dev/mapper/vg-lv → /dev/dm-X
// It also handled block devices.
func (s *SysfsStorageInfoProvider) getLVMDMDevice(device string) []string {
	if !strings.HasPrefix(device, "/dev/mapper/") {
		return nil
	}
	hostMapperPath := filepath.Join(s.hostRootPath, device)

	var stat unix.Stat_t
	if err := unix.Lstat(hostMapperPath, &stat); err != nil {
		s.log.Errorf("cannot read stat of %s: %v", hostMapperPath, err)
		return nil
	}

	switch stat.Mode & unix.S_IFMT {
	// It is most common for devices under /dev/mapper to be symlinks, so check this first.
	case unix.S_IFLNK:
		linkTarget, err := os.Readlink(hostMapperPath)
		if err != nil {
			s.log.Errorf("symlink resolution failed for %s: %v", device, err)
			return nil
		}
		return []string{"/dev/" + filepath.Base(linkTarget)}

	// Devices under /dev/mapper can also be block devices.
	case unix.S_IFBLK:
		return s.findDMDeviceByMajorMinor(hostMapperPath, stat.Rdev)

	default:
		s.log.Errorf("unhandled file type for %s: %d", hostMapperPath, stat.Mode)
		return nil
	}
}

func (s *SysfsStorageInfoProvider) CollectBlockDeviceMetrics(ctx context.Context, timestamp time.Time) ([]BlockDeviceMetric, error) {
	// Read stats from /proc/diskstats
	diskStats, err := readProcDiskStats()
	if err != nil {
		return nil, fmt.Errorf("failed to read disk stats: %w", err)
	}

	blockMetrics := make([]BlockDeviceMetric, 0, len(diskStats))

	for deviceName, stats := range diskStats {
		current := s.buildBlockDeviceMetric(ctx, deviceName, stats, timestamp)

		prev, exists := s.storageState.blockDevices[current.Name]
		if exists {
			timeDiff := current.Timestamp.Sub(prev.Timestamp).Seconds()
			if timeDiff > 0 {
				s.calculateBlockDeviceRates(&current, prev, timeDiff)
				blockMetrics = append(blockMetrics, current)
			}
		}

		s.storageState.blockDevices[current.Name] = &current
	}

	return blockMetrics, nil
}

func (s *SysfsStorageInfoProvider) getCurrentCloudProvider() (types.Type, error) {
	n, err := s.getNode()
	if err != nil {
		return "", err
	}

	return types.NewProviderType(n.CloudProvider)
}

func (s *SysfsStorageInfoProvider) findAWSXenVolumeIDForDisk(ctx context.Context, deviceName string) (string, error) {
	// For Xen instances devices are always exposed under /dev/xvd*. * in matches the name
	// of the mapping as specifid in the AWS console. There is nothing exposed by the Xen
	// driver that helps to extract the volume ID, hence all mapped volumes on the device
	//	need to be searched.
	//
	// For example:
	// 	one mapping of vol-1234abc to /dev/sdx
	// becomes
	// 		/dev/xvdx
	resp, err := s.getNodeCloudVolumes(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get cloud volumes for %s: %w", s.nodeName, err)
	}

	devicePath := "/dev/" + deviceName
	adjustedDevicePath := strings.Replace(devicePath, "xvd", "sd", 1)

	for _, cvi := range resp.Volumes {
		awsInfo := cvi.GetAwsInfo()
		if awsInfo == nil {
			continue
		}

		if awsInfo.Device == devicePath || awsInfo.Device == adjustedDevicePath {
			return cvi.VolumeId, nil
		}
	}

	s.log.With(
		"device", deviceName,
		"adjustedDevicePath", adjustedDevicePath,
	).Debug("could not find matching volume for xen based instance")

	return "", nil
}

func (s *SysfsStorageInfoProvider) findAWSNitroVolumeIDForDisk(deviceName string) (string, error) {
	devicePath := filepath.Join(s.sysBlockPrefix, "sys", "block", deviceName)
	modelPath := filepath.Join(devicePath, "device", "model")

	modelData, err := readFileTrimmed(modelPath)
	if err != nil {
		return "", fmt.Errorf("error reading device model of `%s`: %w", deviceName, err)
	}

	// We only care about AWS EBS devices.
	if string(modelData) != "Amazon Elastic Block Store" {
		s.log.With(
			"device", deviceName,
			"model", string(modelData),
		).Debug("got non AWS model")
		return "", nil
	}

	serialPath := filepath.Join(devicePath, "device", "serial")
	serialData, err := readFileTrimmed(serialPath)
	if err != nil {
		return "", fmt.Errorf("error reading device serial of `%s`: %w", deviceName, err)
	}

	serial := string(serialData)

	if rawSerial, found := strings.CutPrefix(serial, "vol"); found {
		// We want the serial in format `vol-`.
		return "vol-" + rawSerial, nil
	} else {
		s.log.With("serial", serial).Warn("got serial for EBS device without `vol` prefix")
		return "", nil
	}
}

func extractSCSIDiskName(device string) string {
	num := strings.IndexFunc(device, func(r rune) bool {
		return r >= '0' && r <= '9'
	})

	// For SCSI devices a number indicates that we got a partitoin.
	if num > 0 {
		return device[0:num]
	}

	return device
}

func extractNVMeDiskName(device string) string {
	num := strings.IndexRune(device, 'p')

	// NVMe partitions contain a `p` in the device name.
	if num > 0 {
		return device[0:num]
	}

	return device
}

func (s *SysfsStorageInfoProvider) findAWSVolumeIDForDisk(ctx context.Context, deviceName string) (string, error) {
	switch {
	case strings.HasPrefix(deviceName, "xvd"):
		diskName := extractSCSIDiskName(deviceName)

		s.log.With(
			"device", deviceName,
			"disk", diskName,
		).Debug("extract AWS volume id for Xen based instance")

		return s.findAWSXenVolumeIDForDisk(ctx, diskName)

	case strings.HasPrefix(deviceName, "nvme"):
		diskName := extractNVMeDiskName(deviceName)

		s.log.With(
			"device", deviceName,
			"disk", diskName,
		).Debug("extract AWS volume id for Nitro based instance")

		return s.findAWSNitroVolumeIDForDisk(diskName)

	}

	s.log.With("device", deviceName).Info("unsupported disk type")

	return "", nil
}

// extractIdentifierFromVDP83h extracts the identifier of the given raw data
// according to Vital Product Data page 83 specification. For more details see
// page 364 of
// https://www.seagate.com/files/staticfiles/support/docs/manual/Interface%20manuals/100293068h.pdf
// The function will always return the fist identifier encountered, as it seems
// like GCP always will provide a single identifier.
func extractGCPIdentifierFromVDP83h(rawData []byte) (string, error) {
	// Page length is encoded in BigEndian.
	pageLength := (int32(rawData[2])<<8 | int32(rawData[3]))

	// The page length sepcifies the data length minus the header (4 bytes).
	if pageLength != int32(len(rawData))-4 { // nolint:gosec
		// TODO(patrick.pichler): should this be a warning instead of an hard error?
		return "", fmt.Errorf("page length %d is not equals len of read data (%d)", pageLength, len(rawData)-4)
	}

	identifierData := rawData[4:]
	identifierLength := identifierData[3]

	// Ensure that the data contains the full identifier as specified by length.
	if len(identifierData)-4 < int(identifierLength) {
		return "", fmt.Errorf("identifier length %d is bigger than remaining data (%d)", pageLength, len(identifierData)-4)
	}

	return string(identifierData[4 : 4+identifierLength]), nil
}

func readFileTrimmed(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return bytes.TrimSpace(data), nil
}

func (s *SysfsStorageInfoProvider) extractGCPDeviceNameForSCSIDisk(deviceName string) (string, error) {
	devicePath := filepath.Join(s.sysBlockPrefix, "sys", "block", deviceName)
	vendorPath := filepath.Join(devicePath, "device", "vendor")

	vendorData, err := readFileTrimmed(vendorPath)
	if err != nil {
		return "", fmt.Errorf("error reading device vendor of `%s`: %w", deviceName, err)
	}

	// We only care about Google type disks.
	if string(vendorData) != "Google" {
		return "", nil
	}

	// The disk name is encoded in the Vital Product Data page 83.
	vdp83Path := filepath.Join(devicePath, "device", "vpd_pg83")
	vdp83Data, err := os.ReadFile(vdp83Path)
	if err != nil {
		return "", fmt.Errorf("error reading vdp_pg83 of `%s`: %w", deviceName, err)
	}

	volumeID, err := extractGCPIdentifierFromVDP83h(vdp83Data)
	if err != nil {
		return "", fmt.Errorf("error while parsing VDP 83 of device `%s`: %w", deviceName, err)
	}

	return volumeID, nil
}

func (s *SysfsStorageInfoProvider) extractGCPDeviceNameForNVMeDisk(deviceName string) (string, error) {
	devicePath := filepath.Join(s.sysBlockPrefix, "sys", "block", deviceName)
	deviceModelPath := filepath.Join(devicePath, "device", "model")

	modelData, err := readFileTrimmed(deviceModelPath)
	if err != nil {
		return "", fmt.Errorf("error reading device serial of `%s`: %w", deviceName, err)
	}

	// Ensure device is a persistent disk. This is required, as local SSDs are also mounted
	// using the NVMe driver.
	if string(modelData) != "nvme_card-pd" {
		return "", nil
	}

	devPath := filepath.Join(devicePath, "dev")
	deviceNumberData, err := readFileTrimmed(devPath)
	if err != nil {
		return "", fmt.Errorf("error reading device number of `%s`: %w", deviceName, err)
	}

	// GCP mounts persitent volumes under the same NVMe device in different namespaces. To
	// extract the ID, kvisor would need to communicate directly with the NVMe device, which
	// is only possible in a privileged container. To work around this, we try to retrieve the
	// serial from the udev db. This solution is not perfect, as it requries certain udev rules
	// to be present, but good enough for now.
	udevDBPath := filepath.Join(s.hostRootPath, "run", "udev", "data", "b"+string(deviceNumberData))
	udevDBFile, err := os.Open(udevDBPath)
	if err != nil {
		s.log.Errorf("failed to open udev database for device %s: %v", deviceName, err)
		return "", nil
	}
	defer udevDBFile.Close()

	tags, err := parseUDevDB(udevDBFile, map[string]string{
		"ID_SERIAL_SHORT": "serial",
	})
	if err != nil {
		s.log.With(
			"device", deviceName,
			"error", err,
		).Warn("error while parsing udev db")
		return "", nil
	}

	if serial, found := tags["serial"]; found {
		return serial, nil
	}

	return "", nil
}

func (s *SysfsStorageInfoProvider) findGCPVolumeIDForDisk(ctx context.Context, deviceName string) (string, error) {
	resp, err := s.getNodeCloudVolumes(ctx)
	if err != nil {
		return "", fmt.Errorf("error while fetching node volumes: %w", err)
	}

	// There are no cloud volumes, so nothing we can do to resolve the underlying volume id.
	if len(resp.Volumes) == 0 {
		return "", nil
	}

	var (
		resolvedDeviceName string
	)

	// GCP mounts disks using SCSI or NVMe. All cloud backed volume devices should have either `sd` or `nvme` prefix.
	switch {
	case strings.HasPrefix(deviceName, "sd"):
		deviceName = extractSCSIDiskName(deviceName)

		resolvedDeviceName, err = s.extractGCPDeviceNameForSCSIDisk(deviceName)
	case strings.HasPrefix(deviceName, "nvme"):
		deviceName = extractNVMeDiskName(deviceName)

		resolvedDeviceName, err = s.extractGCPDeviceNameForNVMeDisk(deviceName)

	default:
		// Unsupported disk driver.
		return "", nil
	}

	if err != nil {
		return "", err
	}

	for _, volInfo := range resp.GetVolumes() {
		gcpInfo := volInfo.GetGcpInfo()

		// We need GCP specific information to resolve the volume id.
		if gcpInfo == nil {
			continue
		}

		if gcpInfo.GetDeviceName() == resolvedDeviceName {
			return volInfo.VolumeId, nil
		}
	}

	// TODO(patrick.pichler): should we fall back to the raw resolvedDeviceName name in case
	// the disk was mounted after the last server cache refresh?
	return "", nil
}

func (s *SysfsStorageInfoProvider) buildBlockDeviceMetric(ctx context.Context, blockName string, stats DiskStats, timestamp time.Time) BlockDeviceMetric {
	// Get device metadata
	diskType := s.getDiskType(blockName)

	// Check if this is a partition to find parent device
	partitionOf := ""
	deviceType := s.getDeviceType(blockName)
	if deviceType == "partition" {
		partitionOf = s.getPartitionParent(blockName)
	}

	holders := s.getHolders(blockName)
	raidLevel := s.getRaidLevel(blockName)
	logicalSectorSize := s.getLogicalSectorSize(blockName)
	lvmInfo := s.getLVMInfo(blockName)

	diskSize, err := s.getDeviceSize(blockName)
	if err != nil {
		s.log.Debugf("failed to get disk size for %s: %v", blockName, err)
	}

	nodeTemplate, err := s.getNodeTemplate()
	if err != nil {
		s.log.Debugf("failed to get node template for %s: %v", blockName, err)
	}

	var volumeID string

	cloudProvider, err := s.getCurrentCloudProvider()
	if err != nil {
		s.log.Debugf("failed to get current cloud provider: %v", err)
	} else {
		switch cloudProvider {
		case types.TypeAWS:
			awsVolumeId, err := s.findAWSVolumeIDForDisk(ctx, blockName)
			if err != nil {
				s.log.
					With(
						"error", err,
						"device", blockName,
					).
					Warn("issue while resolving aws volume id")
				break
			}

			// VolumeID could not be resolved. This can happen as not all volumes are EBS backed.
			if awsVolumeId == "" {
				break
			}

			volumeID = awsVolumeId
		case types.TypeGCP:
			gcpVolumeId, err := s.findGCPVolumeIDForDisk(ctx, blockName)
			if err != nil {
				s.log.
					With(
						"error", err,
						"device", blockName,
					).
					Warn("issue while resolving aws volume id")
				break
			}
			// VolumeID could not be resolved. This can happen as not all volumes are GCP owned.
			if gcpVolumeId == "" {
				break
			}

			volumeID = gcpVolumeId
		}
	}

	return BlockDeviceMetric{
		Name:             blockName,
		NodeName:         s.nodeName,
		NodeTemplate:     nodeTemplate,
		Path:             filepath.Join("/dev", blockName),
		SizeBytes:        diskSize,
		DiskType:         diskType,
		PartitionOf:      partitionOf,
		Holders:          holders,
		IsVirtual:        isVirtualDevice(blockName),
		RaidLevel:        raidLevel,
		LVMInfo:          lvmInfo,
		Timestamp:        timestamp,
		InFlightRequests: safeUint64ToInt64(stats.InFlight),
		CloudVolumeID:    volumeID,

		// Internal fields for delta calculation
		logicalSectorSize: logicalSectorSize,
		readIOs:           stats.ReadIOs,
		writeIOs:          stats.WriteIOs,
		readSectors:       stats.ReadSectors,
		writeSectors:      stats.WriteSectors,
		readTicks:         stats.ReadTicks,
		writeTicks:        stats.WriteTicks,
		ioTicks:           stats.IOTicks,
		timeInQueue:       stats.TimeInQueue,
	}
}

func (s *SysfsStorageInfoProvider) calculateBlockDeviceRates(current *BlockDeviceMetric, prev *BlockDeviceMetric, timeDiff float64) {
	if timeDiff <= 0 {
		return
	}

	// Calculate deltas
	deltaReadIOs := float64(current.readIOs - prev.readIOs)
	deltaWriteIOs := float64(current.writeIOs - prev.writeIOs)
	deltaReadSectors := float64(current.readSectors - prev.readSectors)
	deltaWriteSectors := float64(current.writeSectors - prev.writeSectors)
	deltaReadTicks := float64(current.readTicks - prev.readTicks)
	deltaWriteTicks := float64(current.writeTicks - prev.writeTicks)
	deltaIOTicks := float64(current.ioTicks - prev.ioTicks)
	deltaTimeInQueue := float64(current.timeInQueue - prev.timeInQueue)

	// Calculate rates
	current.ReadIOPS = deltaReadIOs / timeDiff
	current.WriteIOPS = deltaWriteIOs / timeDiff

	// Use actual logical sector size for throughput
	sectorSize := float64(current.logicalSectorSize)
	current.ReadThroughputBytes = (deltaReadSectors * sectorSize) / timeDiff
	current.WriteThroughputBytes = (deltaWriteSectors * sectorSize) / timeDiff

	// Calculate latencies (average time per operation in milliseconds)
	current.ReadLatencyMs = safeDiv(deltaReadTicks, deltaReadIOs)
	current.WriteLatencyMs = safeDiv(deltaWriteTicks, deltaWriteIOs)

	// Calculate average queue depth
	current.AvgQueueDepth = safeDiv(deltaTimeInQueue, timeDiff*1000.0)

	// Calculate utilization (fraction of time with I/O operations, 0-1)
	current.Utilization = safeDiv(deltaIOTicks, timeDiff*1000.0)
}

// getDeviceSize - reads from /sys/block/<device>/size or /sys/block/<parent>/<partition>/size
func (s *SysfsStorageInfoProvider) getDeviceSize(deviceName string) (*int64, error) {
	devicePath := filepath.Join(s.sysBlockPrefix, "sys", "block", deviceName, "size")
	if sectors, err := s.getDeviceSectorCount(devicePath); err == nil && sectors > 0 {
		return lo.ToPtr(sectors * sectorSizeBytes), nil
	}

	if sectors, err := s.getPartitionSectorCount(deviceName); err == nil && sectors > 0 {
		return lo.ToPtr(sectors * sectorSizeBytes), nil
	}

	return nil, fmt.Errorf("failed to get size for device %s", deviceName)
}

func (s *SysfsStorageInfoProvider) getDeviceSectorCount(devicePath string) (int64, error) {
	data, err := os.ReadFile(devicePath)
	if err != nil {
		return 0, err
	}

	sizeStr := strings.TrimSpace(string(data))
	sectors, err := strconv.ParseInt(sizeStr, 10, 64)
	if err != nil {
		return 0, err
	}

	return sectors, nil
}

func (s *SysfsStorageInfoProvider) getPartitionSectorCount(deviceName string) (int64, error) {
	blockDir := filepath.Join(s.sysBlockPrefix, "sys", "block")
	entries, err := os.ReadDir(blockDir)
	if err != nil {
		return 0, err
	}

	for _, entry := range entries {
		entryPath := filepath.Join(blockDir, entry.Name())
		stat, err := os.Stat(entryPath)
		if err != nil || !stat.IsDir() {
			continue
		}

		partitionPath := filepath.Join(blockDir, entry.Name(), deviceName, "size")
		if sectors, err := s.getDeviceSectorCount(partitionPath); err == nil && sectors > 0 {
			return sectors, nil
		}
	}

	return 0, fmt.Errorf("partition %s not found", deviceName)
}

func isLVMDevice(deviceName string) bool {
	return strings.HasPrefix(deviceName, "dm-")
}

func isRAIDDevice(deviceName string) bool {
	return strings.HasPrefix(deviceName, "md")
}

func isVirtualDevice(deviceName string) bool {
	return isLVMDevice(deviceName) || isRAIDDevice(deviceName)
}

func (s *SysfsStorageInfoProvider) getDeviceType(blockName string) string {
	devicePath := filepath.Join(s.sysBlockPrefix, "sys", "block", blockName)

	// Check if device exists in /sys/block (top-level device)
	// Source: /sys/block/<device>/
	if _, err := os.Stat(devicePath); os.IsNotExist(err) {
		return "partition"
	}

	// Check for device-mapper (LVM)
	// Source: /sys/block/<device>/dm/uuid
	if isLVMDevice(blockName) {
		uuidPath := filepath.Join(devicePath, "dm", "uuid")
		if uuid, err := os.ReadFile(uuidPath); err == nil {
			if strings.HasPrefix(string(uuid), "LVM-") {
				return "lvm"
			}
		}
		return "device-mapper"
	}

	// Check for RAID
	// Source: /sys/block/<device>/md/
	if isRAIDDevice(blockName) {
		mdPath := filepath.Join(devicePath, "md")
		if _, err := os.Stat(mdPath); err == nil {
			return "raid"
		}
	}

	// Check for virtual devices with slaves
	// Source: /sys/block/<device>/slaves/
	slavesPath := filepath.Join(devicePath, "slaves")
	if entries, err := os.ReadDir(slavesPath); err == nil && len(entries) > 0 {
		return "virtual"
	}

	return "physical"
}

// getPartitionParent - reads from /sys/block/<parent>/<partition>/
func (s *SysfsStorageInfoProvider) getPartitionParent(partition string) string {
	blockDir := filepath.Join(s.sysBlockPrefix, "sys", "block")
	entries, err := os.ReadDir(blockDir)
	if err != nil {
		return ""
	}

	for _, entry := range entries {
		partPath := filepath.Join(blockDir, entry.Name(), partition)
		if _, err := os.Stat(partPath); err == nil {
			return entry.Name()
		}
	}

	return ""
}

// getRaidLevel - reads from /sys/block/<device>/md/level
func (s *SysfsStorageInfoProvider) getRaidLevel(deviceName string) string {
	if !isRAIDDevice(deviceName) {
		return ""
	}

	levelPath := filepath.Join(s.sysBlockPrefix, "sys", "block", deviceName, "md", "level")
	data, err := os.ReadFile(levelPath)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(data))
}

// getLogicalSectorSize - reads from /sys/block/<device>/queue/logical_block_size
func (s *SysfsStorageInfoProvider) getLogicalSectorSize(deviceName string) uint64 {
	sizePath := filepath.Join(s.sysBlockPrefix, "sys", "block", deviceName, "queue", "logical_block_size")
	data, err := os.ReadFile(sizePath)
	if err != nil {
		return 512 // fallback to default
	}

	size, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 512
	}

	return size
}

// getDiskType - reads from /sys/block/<device>/queue/rotational
// For partitions, inherits the disk type from the parent device
func (s *SysfsStorageInfoProvider) getDiskType(deviceName string) string {
	// Check if device has its own queue/rotational file
	rotPath := filepath.Join(s.sysBlockPrefix, "sys", "block", deviceName, "queue", "rotational")
	data, err := os.ReadFile(rotPath)
	if err != nil {
		// If reading fails (e.g., for partitions), try to get parent's disk type
		deviceType := s.getDeviceType(deviceName)
		if deviceType == "partition" {
			parent := s.getPartitionParent(deviceName)
			if parent != "" {
				// Recursively get parent's disk type
				return s.getDiskType(parent)
			}
		}
		return ""
	}

	rotational := strings.TrimSpace(string(data))
	if rotational == "0" {
		return "SSD"
	}
	return "HDD"
}

// getHolders - reads from /sys/block/<device>/holders/
func (s *SysfsStorageInfoProvider) getHolders(deviceName string) []string {
	holdersPath := filepath.Join(s.sysBlockPrefix, "sys", "block", deviceName, "holders")
	entries, err := os.ReadDir(holdersPath)
	if err != nil {
		return nil
	}

	var holders []string
	for _, entry := range entries {
		holders = append(holders, entry.Name())
	}

	return holders
}

func parseUDevDB(f io.Reader, wantedTags map[string]string) (map[string]string, error) {
	tags := make(map[string]string, len(wantedTags))

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		// Only process device property lines (E:)
		property, found := strings.CutPrefix(line, "E:")

		if !found {
			continue
		}

		parts := strings.SplitN(property, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key, value := parts[0], parts[1]
		if name, ok := wantedTags[key]; ok && value != "" {
			tags[name] = value
		}

		// Exit early if desired tags are found
		if len(tags) == len(wantedTags) {
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return tags, nil
}

// getLVMInfo returns LVM metadata (dm_name, lv_name, vg_name) for device-mapper devices
func (s *SysfsStorageInfoProvider) getLVMInfo(deviceName string) map[string]string {
	if !strings.HasPrefix(deviceName, "dm-") {
		return nil
	}

	// Read device major:minor from /sys/block/<device>/dev
	devPath := filepath.Join(s.sysBlockPrefix, "sys", "block", deviceName, "dev")
	devData, err := os.ReadFile(devPath)
	if err != nil {
		return nil
	}

	majorMinor := strings.TrimSpace(string(devData))
	if majorMinor == "" {
		return nil
	}

	// Open udev database file from host: /proc/1/root/run/udev/data/b<major>:<minor>
	udevDBPath := filepath.Join(s.hostRootPath, "run", "udev", "data", "b"+majorMinor)
	udevDBFile, err := os.Open(udevDBPath)
	if err != nil {
		return nil
	}
	defer udevDBFile.Close()

	tags, err := parseUDevDB(udevDBFile, map[string]string{
		"DM_NAME":    "dm_name",
		"DM_LV_NAME": "lv_name",
		"DM_VG_NAME": "vg_name",
	})
	if err != nil {
		s.log.Errorf("failed to scan udev database for device %s: %v", deviceName, err)
		return nil
	}

	return tags
}

func safeUint64ToInt64(val uint64) int64 {
	if val > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(val)
}

func safeInt64ToUint64(val int64) uint64 {
	if val < 0 {
		return 0
	}
	return uint64(val)
}

func safeDiv(numerator, denominator float64) float64 {
	if denominator == 0 {
		return 0
	}
	return numerator / denominator
}

// mountInfo represents a parsed line from /proc/1/mountinfo
type mountInfo struct {
	Device     string
	MountPoint string
	FsType     string
	Options    []string
	MajorMinor string
}

// readMountInfo - reads from /proc/1/mountinfo
func readMountInfo(mountInfoPath string) ([]mountInfo, error) {
	if mountInfoPath == "" {
		mountInfoPath = "/proc/1/mountinfo"
	}

	f, err := os.Open(mountInfoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", mountInfoPath, err)
	}
	defer f.Close()

	var mounts []mountInfo
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}

		mount, err := parseMountInfoLine(line)
		if err != nil {
			// Skip unsupported or malformed lines
			continue
		}
		if mount != nil {
			mounts = append(mounts, *mount)
		}
	}

	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("error scanning %s: %w", mountInfoPath, err)
	}

	return mounts, nil
}

// parseMountInfoLine parses a single line from /proc/1/mountinfo
// Format: <mount id> <parent id> <major:minor> <root> <mount point> <mount options> <optional fields> - <fs type> <mount source> <super options>
func parseMountInfoLine(line string) (*mountInfo, error) {
	// The " - " separator splits the line into two parts
	parts := strings.Split(line, " - ")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid mountinfo format: missing separator")
	}

	left := strings.Fields(parts[0])
	right := strings.Fields(parts[1])

	if len(left) < 6 || len(right) < 2 {
		return nil, fmt.Errorf("insufficient fields in mountinfo line")
	}

	majorMinor := left[2]
	mountPoint := left[4]
	mountOptions := strings.Split(left[5], ",")
	fsType := right[0]
	device := right[1]

	// Filter to only supported filesystem types
	if !isSupportedFilesystem(fsType) {
		return nil, nil // Not an error, just not supported
	}

	return &mountInfo{
		Device:     device,
		MountPoint: mountPoint,
		FsType:     fsType,
		Options:    mountOptions,
		MajorMinor: majorMinor,
	}, nil
}

func isSupportedFilesystem(fsType string) bool {
	switch fsType {
	case "ext4", "xfs", "btrfs", "ext3", "ext2":
		return true
	default:
		return false
	}
}

// getFilesystemStats - takes data from syscall.Statfs() system call
func getFilesystemStats(mountPoint string) (sizeBytes, usedBytes int64, totalInodes, usedInodes int64, dev uint64, err error) {
	var statfs syscall.Statfs_t
	err = syscall.Statfs(mountPoint, &statfs)
	if err != nil {
		return 0, 0, 0, 0, 0, fmt.Errorf("failed to statfs %s: %w", mountPoint, err)
	}

	var devID uint64
	var mountPointStat unix.Stat_t
	err = unix.Stat(mountPoint, &mountPointStat)
	if err == nil {
		devID = uint64(mountPointStat.Dev)
	}

	// statfs.Bsize is uint32 on Darwin, int64 on Linux - convert safely to uint64
	blockSize := safeInt64ToUint64(int64(statfs.Bsize))
	if blockSize == 0 {
		blockSize = 512 // fallback to default block size
	}

	// Calculate block-based metrics
	totalBlocks := statfs.Blocks
	freeBlocks := statfs.Bfree
	usedBlocks := totalBlocks - freeBlocks

	// Convert to bytes
	totalSizeBytes := totalBlocks * blockSize
	usedSpaceBytes := usedBlocks * blockSize

	// Inode statistics
	totalInodesVal := statfs.Files
	usedInodesVal := totalInodesVal - statfs.Ffree

	return safeUint64ToInt64(totalSizeBytes),
		safeUint64ToInt64(usedSpaceBytes),
		safeUint64ToInt64(totalInodesVal),
		safeUint64ToInt64(usedInodesVal),
		devID,
		nil
}

func getDeviceIDForPath(path string) (uint64, error) {
	var stat unix.Stat_t

	err := unix.Stat(path, &stat)
	if err != nil {
		return 0, err
	}

	return uint64(stat.Dev), nil
}

func buildFilesystemLabels(log *logging.Logger, fsMountPointDeviceID uint64, wellKnownPathsDeviceID map[string]uint64) map[string]string {
	labels := make(map[string]string)
	if devID, ok := wellKnownPathsDeviceID[kubeletPath]; ok {
		if devID == fsMountPointDeviceID {
			labels["kubelet"] = "true"
		}
	}

	if devID, ok := wellKnownPathsDeviceID[containerdPath]; ok {
		if devID == fsMountPointDeviceID {
			labels["containerd"] = "true"
		}
	}

	if devID, ok := wellKnownPathsDeviceID[crioPath]; ok {
		if devID == fsMountPointDeviceID {
			labels["crio"] = "true"
		}
	}

	castaiStorageResolvedPath := filepath.Join(hostPathRoot, castaiStoragePath)
	castaiStorageDeviceID, err := getDeviceIDForPath(castaiStorageResolvedPath)
	if err == nil {
		if castaiStorageDeviceID == fsMountPointDeviceID {
			labels["castai-storage"] = "true"
		}
	} else if !os.IsNotExist(err) {
		log.With("path", castaiStorageResolvedPath).
			With("error", err).
			Warn("failed to get device ID for castai storage path")
	}

	return labels
}
