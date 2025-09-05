package pipeline

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/elastic/go-freelru"
	"github.com/shirou/gopsutil/v4/disk"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"

	kubepb "github.com/castai/kvisor/api/v1/kube"
	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/config"
	"github.com/castai/kvisor/cmd/agent/daemon/enrichment"
	"github.com/castai/kvisor/cmd/agent/daemon/export"
	"github.com/castai/kvisor/cmd/agent/daemon/metrics"
	"github.com/castai/kvisor/cmd/agent/daemon/netstats"
	"github.com/castai/kvisor/pkg/cgroup"
	"github.com/castai/kvisor/pkg/containers"
	"github.com/castai/kvisor/pkg/ebpftracer"
	"github.com/castai/kvisor/pkg/ebpftracer/events"
	"github.com/castai/kvisor/pkg/ebpftracer/signature"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/castai/kvisor/pkg/processtree"
	custommetrics "github.com/castai/metrics"
)

type DiskInterface interface {
	IOCounters() (map[string]disk.IOCountersStat, error)
	Partitions(all bool) ([]disk.PartitionStat, error)
	Usage(path string) (*disk.UsageStat, error)
}

type DiskClient struct{}

func NewDiskClient() *DiskClient {
	return &DiskClient{}
}

func (d *DiskClient) IOCounters() (map[string]disk.IOCountersStat, error) {
	return disk.IOCounters()
}

func (d *DiskClient) Partitions(all bool) ([]disk.PartitionStat, error) {
	return disk.Partitions(all)
}

func (d *DiskClient) Usage(path string) (*disk.UsageStat, error) {
	return disk.Usage(path)
}

type Config struct {
	DataBatch   config.DataBatchConfig   `validate:"required"`
	Netflow     config.NetflowConfig     `validate:"required"`
	Events      config.EventsConfig      `validate:"required"`
	Stats       config.StatsConfig       `validate:"required"`
	ProcessTree config.ProcessTreeConfig `validate:"required"`
}

type containersClient interface {
	ListContainers(filter func(c *containers.Container) bool) []*containers.Container
	GetOrLoadContainerByCgroupID(ctx context.Context, cgroupID uint64) (*containers.Container, error)
	CleanupByCgroupID(cgroupID cgroup.ID)
	GetCgroupsInNamespace(namespace string) []uint64
	RegisterContainerCreatedListener(l containers.ContainerCreatedListener)
	RegisterContainerDeletedListener(l containers.ContainerDeletedListener)
	GetCgroupStats(c *containers.Container) (cgroup.Stats, error)
}

type netStatsReader interface {
	Read(pid uint32) ([]netstats.InterfaceStats, error)
}

type ebpfTracer interface {
	Events() <-chan *types.Event
	MuteEventsFromCgroup(cgroup uint64, reason string) error
	MuteEventsFromCgroups(cgroups []uint64, reason string) error
	UnmuteEventsFromCgroup(cgroup uint64) error
	UnmuteEventsFromCgroups(cgroups []uint64) error
	IsCgroupMuted(cgroup uint64) bool
	ReadSyscallStats() (map[ebpftracer.SyscallStatsKeyCgroupID][]ebpftracer.SyscallStats, error)
	CollectNetworkSummary() ([]ebpftracer.TrafficKey, []ebpftracer.TrafficSummary, error)
	CollectFileAccessStats() ([]ebpftracer.FileAccessKey, []ebpftracer.FileAccessStats, error)
	GetEventName(id events.ID) string
}

type signatureEngine interface {
	Events() <-chan signature.Event
}

type conntrackClient interface {
	GetDestination(src, dst netip.AddrPort) (netip.AddrPort, bool)
}

type processTreeCollector interface {
	GetCurrentProcesses(ctx context.Context) ([]processtree.ProcessEvent, error)
}

type procHandler interface {
	PSIEnabled() bool
	GetPSIStats(file string) (*castaipb.PSIStats, error)
	GetMeminfoStats() (*castaipb.MemoryStats, error)
}

type enrichmentService interface {
	Enqueue(e *enrichment.EnrichedContainerEvent) bool
	Events() <-chan *enrichment.EnrichedContainerEvent
}

type BlockDeviceMetricsWriter interface {
	Write(metrics ...BlockDeviceMetrics) error
}

type FilesystemMetricsWriter interface {
	Write(metrics ...FilesystemMetrics) error
}

// NewBlockDeviceMetricsWriter creates a new block device metrics writer
func NewBlockDeviceMetricsWriter(metricsClient custommetrics.MetricClient) (BlockDeviceMetricsWriter, error) {
	return custommetrics.NewMetric[BlockDeviceMetrics](
		metricsClient,
		custommetrics.WithCollectionName[BlockDeviceMetrics]("kvisor_block_device_metrics"),
		custommetrics.WithSkipTimestamp[BlockDeviceMetrics](),
	)
}

// NewFilesystemMetricsWriter creates a new filesystem metrics writer
func NewFilesystemMetricsWriter(metricsClient custommetrics.MetricClient) (FilesystemMetricsWriter, error) {
	return custommetrics.NewMetric[FilesystemMetrics](
		metricsClient,
		custommetrics.WithCollectionName[FilesystemMetrics]("kvisor_filesystem_metrics"),
		custommetrics.WithSkipTimestamp[FilesystemMetrics](),
	)
}

func NewController(
	log *logging.Logger,
	cfg Config,
	exporters []export.DataBatchWriter,
	containersClient containersClient,
	netStatsReader netStatsReader,
	ct conntrackClient,
	tracer ebpfTracer,
	signatureEngine signatureEngine,
	kubeClient kubepb.KubeAPIClient,
	processTreeCollector processTreeCollector,
	procHandler procHandler,
	enrichmentService enrichmentService,
	blockDeviceMetrics BlockDeviceMetricsWriter,
	filesystemMetrics FilesystemMetricsWriter,
	diskClient DiskInterface,
) *Controller {
	dnsCache, err := freelru.NewSynced[uint64, *freelru.SyncedLRU[netip.Addr, string]](1024, func(k uint64) uint32 {
		return uint32(k) // nolint:gosec
	})
	if err != nil {
		panic(err)
	}
	podCache, err := freelru.NewSynced[string, *kubepb.Pod](256, func(k string) uint32 {
		return uint32(xxhash.Sum64String(k)) // nolint:gosec
	})
	if err != nil {
		panic(err)
	}

	return &Controller{
		log:                  log.WithField("component", "ctrl"),
		cfg:                  cfg,
		exporters:            exporters,
		containersClient:     containersClient,
		netStatsReader:       netStatsReader,
		ct:                   ct,
		tracer:               tracer,
		signatureEngine:      signatureEngine,
		kubeClient:           kubeClient,
		nodeName:             os.Getenv("NODE_NAME"),
		mutedNamespaces:      map[string]struct{}{},
		dnsCache:             dnsCache,
		podCache:             podCache,
		processTreeCollector: processTreeCollector,
		procHandler:          procHandler,
		enrichmentService:    enrichmentService,

		eventGroups:          make(map[uint64]*containerEventsGroup),
		containerStatsGroups: make(map[uint64]*containerStatsGroup),

		blockDeviceMetrics: blockDeviceMetrics,
		filesystemMetrics:  filesystemMetrics,
		diskClient:         diskClient,
		storageState: &storageMetricsState{
			blockDevices: make(map[string]*BlockDeviceMetrics),
			filesystems:  make(map[string]*FilesystemMetrics),
		},
	}
}

type Controller struct {
	log                  *logging.Logger
	cfg                  Config
	containersClient     containersClient
	netStatsReader       netStatsReader
	ct                   conntrackClient
	tracer               ebpfTracer
	signatureEngine      signatureEngine
	processTreeCollector processTreeCollector
	exporters            []export.DataBatchWriter
	procHandler          procHandler
	enrichmentService    enrichmentService

	nodeName string

	mutedNamespacesMu sync.RWMutex
	mutedNamespaces   map[string]struct{}

	clusterInfo    *clusterInfo
	kubeClient     kubepb.KubeAPIClient
	dnsCache       *freelru.SyncedLRU[uint64, *freelru.SyncedLRU[netip.Addr, string]]
	podCache       *freelru.SyncedLRU[string, *kubepb.Pod]
	conntrackCache *freelru.LRU[types.AddrTuple, netip.AddrPort]

	eventGroups          map[uint64]*containerEventsGroup
	containerStatsGroups map[uint64]*containerStatsGroup

	// Storage metrics
	blockDeviceMetrics BlockDeviceMetricsWriter
	filesystemMetrics  FilesystemMetricsWriter
	diskClient         DiskInterface
	storageState       *storageMetricsState
}

func (c *Controller) Run(ctx context.Context) error {
	c.log.Infof("running")
	defer c.log.Infof("stopping")

	c.containersClient.RegisterContainerCreatedListener(c.onNewContainer)
	c.containersClient.RegisterContainerDeletedListener(c.onDeleteContainer)

	errg, ctx := errgroup.WithContext(ctx)
	if c.cfg.Events.Enabled {
		errg.Go(func() error {
			return c.runEventsPipeline(ctx)
		})
	}
	if c.cfg.Stats.Enabled || c.cfg.Stats.FileAccessEnabled {
		errg.Go(func() error {
			return c.runStatsPipeline(ctx)
		})
	}
	if c.cfg.Netflow.Enabled {
		// Conntrack cache is used only in netflow pipeline.
		// It's safe to use non synced lru since it's accessed form one goroutine.
		conntrackCacheKey := xxhash.New()
		conntrackCache, err := freelru.New[types.AddrTuple, netip.AddrPort](1024, func(k types.AddrTuple) uint32 {
			conntrackCacheKey.Reset()
			src, _ := k.Src.MarshalBinary()
			dst, _ := k.Dst.MarshalBinary()
			_, _ = conntrackCacheKey.Write(src)
			_, _ = conntrackCacheKey.Write(dst)
			return uint32(conntrackCacheKey.Sum64()) // nolint:gosec
		})
		// TODO(anjmao): All lru caches should export metrics. We may have too large or too small sizes.
		if err != nil {
			panic(err)
		}
		c.conntrackCache = conntrackCache

		errg.Go(func() error {
			return c.runNetflowPipeline(ctx)
		})
	}

	if c.cfg.ProcessTree.Enabled {
		errg.Go(func() error {
			if err := c.collectInitialProcessTree(ctx); err != nil {
				c.log.Errorf("collecting initial process tree: %v", err)
			}
			return nil
		})
	}

	return errg.Wait()
}

func (c *Controller) sendDataBatch(reason, pipeline string, items []*castaipb.DataBatchItem) {
	start := time.Now()
	var g sync.WaitGroup
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req := &castaipb.WriteDataBatchRequest{
		Items: items,
	}
	size := proto.Size(req)

	for _, exp := range c.exporters {
		g.Add(1)
		go func() {
			defer g.Done()
			if err := exp.Write(ctx, req); err != nil {
				// Only log error. Exporter should handle retries.
				c.log.Errorf("data batch export to %s failed: %v", exp.Name(), err)
				metrics.AgentDataBatchExporterErrorsTotal.WithLabelValues(exp.Name()).Inc()
				return
			}
			metrics.AgentDataBatchExportCallsTotal.WithLabelValues(exp.Name()).Inc()
		}()
	}

	g.Wait()
	c.log.Infof("data batch exported, items=%d, size_bytes=%d, duration=%v, reason=%s", len(items), size, time.Since(start), reason)
	metrics.AgentDataBatchItemsSentTotal.WithLabelValues(pipeline).Add(float64(len(items)))
	metrics.AgentDataBatchBytesSentTotal.WithLabelValues(pipeline).Add(float64(size))
}

func (c *Controller) collectInitialProcessTree(ctx context.Context) error {
	processes, err := c.processTreeCollector.GetCurrentProcesses(ctx)
	if err != nil {
		return err
	}
	processEvents := make([]*castaipb.ProcessEvent, 0, len(processes))
	for _, pe := range processes {
		processEvents = append(processEvents, &castaipb.ProcessEvent{
			Timestamp:   uint64(pe.Timestamp.UnixNano()), // nolint:gosec
			ContainerId: pe.ContainerID,
			Process: &castaipb.Process{
				Pid:             pe.Process.PID,
				StartTime:       uint64(pe.Process.StartTime), // nolint:gosec
				Ppid:            pe.Process.PPID,
				ParentStartTime: uint64(pe.Process.ParentStartTime), // nolint:gosec
				Args:            pe.Process.Args,
				Filepath:        pe.Process.FilePath,
				ExitTime:        pe.Process.ExitTime,
			},
			Action: toProtoProcessAction(pe.Action),
		})
	}
	c.sendDataBatch("initial process tree", metrics.PipelineInitialProcessTree, []*castaipb.DataBatchItem{
		{
			Data: &castaipb.DataBatchItem_ProcessTree{
				ProcessTree: &castaipb.ProcessTreeEvent{
					Initial: true,
					Events:  processEvents,
				},
			},
		},
	})
	return nil
}

func (c *Controller) onNewContainer(container *containers.Container) {
	if c.IsMutedNamespace(container.PodNamespace) {
		// We explicitly mute cgroups of new containers in muted namespaces, as otherwise
		// there could be a timing issue, where we want to mute a namespace before the cgroup mkdir
		// event has been handled.
		err := c.tracer.MuteEventsFromCgroup(container.CgroupID, fmt.Sprintf("new container for muted namespsace %q", container.PodNamespace))
		if err != nil {
			c.log.Warnf("cannot mute cgroup %d: %v", container.CgroupID, err)
		}
	}
}

func (c *Controller) onDeleteContainer(container *containers.Container) {
	c.dnsCache.Remove(container.CgroupID)

	c.log.Debugf("removed cgroup %d", container.CgroupID)
}

func (c *Controller) MuteNamespace(namespace string) error {
	c.mutedNamespacesMu.Lock()
	c.mutedNamespaces[namespace] = struct{}{}
	c.mutedNamespacesMu.Unlock()

	cgroups := c.containersClient.GetCgroupsInNamespace(namespace)

	err := c.tracer.MuteEventsFromCgroups(cgroups, fmt.Sprintf("muted namespace %q", namespace))

	if err != nil {
		return err
	}

	return nil
}

func (c *Controller) UnmuteNamespace(namespace string) error {
	c.mutedNamespacesMu.Lock()
	delete(c.mutedNamespaces, namespace)
	c.mutedNamespacesMu.Unlock()

	cgroups := c.containersClient.GetCgroupsInNamespace(namespace)

	err := c.tracer.UnmuteEventsFromCgroups(cgroups)
	if err != nil {
		return err
	}

	return nil
}

func (c *Controller) IsMutedNamespace(namespace string) bool {
	c.mutedNamespacesMu.RLock()
	defer c.mutedNamespacesMu.RUnlock()
	_, found := c.mutedNamespaces[namespace]

	return found
}

func (c *Controller) getPodInfo(podID string) (*kubepb.Pod, bool) {
	pod, found := c.podCache.Get(podID)
	if !found {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		resp, err := c.kubeClient.GetPod(ctx, &kubepb.GetPodRequest{Uid: podID})
		if err != nil {
			return nil, false
		}
		pod = resp.Pod
		c.podCache.Add(podID, pod)
	}
	return pod, true
}

func workloadKindString(kind kubepb.WorkloadKind) string {
	switch kind {
	case kubepb.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT:
		return "Deployment"
	case kubepb.WorkloadKind_WORKLOAD_KIND_REPLICA_SET:
		return "ReplicaSet"
	case kubepb.WorkloadKind_WORKLOAD_KIND_DAEMON_SET:
		return "DaemonSet"
	case kubepb.WorkloadKind_WORKLOAD_KIND_STATEFUL_SET:
		return "StatefulSet"
	case kubepb.WorkloadKind_WORKLOAD_KIND_JOB:
		return "Job"
	case kubepb.WorkloadKind_WORKLOAD_KIND_CRONJOB:
		return "CronJob"
	case kubepb.WorkloadKind_WORKLOAD_KIND_POD:
		return "Pod"
	default:
		return "Unknown"
	}
}

func toProtoProcessAction(action processtree.ProcessAction) castaipb.ProcessAction {
	switch action {
	case processtree.ProcessExec:
		return castaipb.ProcessAction_PROCESS_ACTION_EXEC
	case processtree.ProcessFork:
		return castaipb.ProcessAction_PROCESS_ACTION_FORK
	case processtree.ProcessExit:
		return castaipb.ProcessAction_PROCESS_ACTION_EXIT
	}
	return castaipb.ProcessAction_PROCESS_ACTION_UNKNOWN
}
