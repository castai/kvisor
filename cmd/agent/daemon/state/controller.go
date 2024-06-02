package state

import (
	"context"
	"net/netip"
	"os"
	"sync"
	"time"

	kubepb "github.com/castai/kvisor/api/v1/kube"
	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/enrichment"
	"github.com/castai/kvisor/cmd/agent/daemon/netstats"
	"github.com/castai/kvisor/pkg/cgroup"
	"github.com/castai/kvisor/pkg/containers"
	"github.com/castai/kvisor/pkg/ebpftracer"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/cespare/xxhash/v2"
	"github.com/elastic/go-freelru"
	"golang.org/x/sync/errgroup"
)

type Config struct {
	ContainerStatsScrapeInterval time.Duration

	NetflowExportInterval time.Duration `validate:"required"`
}

type containersClient interface {
	ListContainers() []*containers.Container
	GetContainerForCgroup(ctx context.Context, cgroup uint64) (*containers.Container, error)
	LookupContainerForCgroupInCache(cgroup uint64) (*containers.Container, bool, error)
	CleanupCgroup(cgroup cgroup.ID)
	GetCgroupsInNamespace(namespace string) []uint64
	RegisterContainerCreatedListener(l containers.ContainerCreatedListener)
	RegisterContainerDeletedListener(l containers.ContainerDeletedListener)
	GetCgroupCpuStats(c *containers.Container) (*cgroup.CPUStat, error)
	GetCgroupMemoryStats(c *containers.Container) (*cgroup.MemoryStat, error)
}

type netStatsReader interface {
	Read(pid uint32) ([]netstats.InterfaceStats, error)
}

type ebpfTracer interface {
	Events() <-chan *types.Event
	NetflowEvents() <-chan *types.Event
	MuteEventsFromCgroup(cgroup uint64) error
	MuteEventsFromCgroups(cgroups []uint64) error
	UnmuteEventsFromCgroup(cgroup uint64) error
	UnmuteEventsFromCgroups(cgroups []uint64) error
	IsCgroupMuted(cgroup uint64) bool
	ReadSyscallStats() (map[ebpftracer.SyscallStatsKeyCgroupID][]ebpftracer.SyscallStats, error)
}

type signatureEngine interface {
	Events() <-chan *castpb.Event
}

type enrichmentService interface {
	Enqueue(e *enrichment.EnrichRequest) bool
	Events() <-chan *castpb.Event
}

type conntrackClient interface {
	GetDestination(src, dst netip.AddrPort) (netip.AddrPort, bool)
}

func NewController(
	log *logging.Logger,
	cfg Config,
	exporters *Exporters,
	containersClient containersClient,
	netStatsReader netStatsReader,
	ct conntrackClient,
	tracer ebpfTracer,
	signatureEngine signatureEngine,
	enrichmentService enrichmentService,
	kubeClient kubepb.KubeAPIClient,
) *Controller {
	dnsCache, err := freelru.NewSynced[uint64, *freelru.SyncedLRU[netip.Addr, string]](1024, func(k uint64) uint32 {
		return uint32(k)
	})
	if err != nil {
		panic(err)
	}
	ipInfoCache, err := freelru.NewSynced[netip.Addr, *kubepb.IPInfo](1024, func(k netip.Addr) uint32 {
		return uint32(xxhash.Sum64(k.AsSlice()))
	})
	if err != nil {
		panic(err)
	}
	podCache, err := freelru.NewSynced[string, *kubepb.Pod](256, func(k string) uint32 {
		return uint32(xxhash.Sum64String(k))
	})
	if err != nil {
		panic(err)
	}
	return &Controller{
		log:                        log.WithField("component", "ctrl"),
		cfg:                        cfg,
		exporters:                  exporters,
		containersClient:           containersClient,
		netStatsReader:             netStatsReader,
		ct:                         ct,
		tracer:                     tracer,
		signatureEngine:            signatureEngine,
		enrichmentService:          enrichmentService,
		kubeClient:                 kubeClient,
		nodeName:                   os.Getenv("NODE_NAME"),
		resourcesStatsScrapePoints: map[uint64]*resourcesStatsScrapePoint{},
		syscallScrapePoints:        map[uint64]*syscallScrapePoint{},
		mutedNamespaces:            map[string]struct{}{},
		dnsCache:                   dnsCache,
		ipInfoCache:                ipInfoCache,
		podCache:                   podCache,
	}
}

type Controller struct {
	log               *logging.Logger
	cfg               Config
	containersClient  containersClient
	netStatsReader    netStatsReader
	ct                conntrackClient
	tracer            ebpfTracer
	signatureEngine   signatureEngine
	enrichmentService enrichmentService
	exporters         *Exporters

	nodeName string

	// Scrape points are used to calculate deltas between scrapes.
	resourcesStatsScrapePointsMu sync.RWMutex
	resourcesStatsScrapePoints   map[uint64]*resourcesStatsScrapePoint
	syscallScrapePointsMu        sync.RWMutex
	syscallScrapePoints          map[uint64]*syscallScrapePoint

	mutedNamespacesMu sync.RWMutex
	mutedNamespaces   map[string]struct{}

	clusterInfo *clusterInfo
	dnsCache    *freelru.SyncedLRU[uint64, *freelru.SyncedLRU[netip.Addr, string]]
	kubeClient  kubepb.KubeAPIClient
	ipInfoCache *freelru.SyncedLRU[netip.Addr, *kubepb.IPInfo]
	podCache    *freelru.SyncedLRU[string, *kubepb.Pod]
}

func (c *Controller) Run(ctx context.Context) error {
	c.log.Infof("running")
	defer c.log.Infof("stopping")

	c.containersClient.RegisterContainerCreatedListener(c.onNewContainer)
	c.containersClient.RegisterContainerDeletedListener(c.onDeleteContainer)

	errg, ctx := errgroup.WithContext(ctx)
	if len(c.exporters.Events) > 0 {
		errg.Go(func() error {
			return c.runEventsPipeline(ctx)
		})
	}
	if len(c.exporters.ContainerStats) > 0 {
		errg.Go(func() error {
			return c.runContainerStatsPipeline(ctx)
		})
	}
	if len(c.exporters.Netflow) > 0 {
		errg.Go(func() error {
			return c.runNetflowPipeline(ctx)
		})
	}
	return errg.Wait()
}

func (c *Controller) onNewContainer(container *containers.Container) {
	if !c.IsMutedNamespace(container.PodNamespace) {
		return
	}

	// We explicitly mute cgroups of new containers in muted namespaces, as otherwise
	// there could be a timing issue, where we want to mute a namespace before the cgroup mkdir
	// event has been handled.
	err := c.tracer.MuteEventsFromCgroup(container.CgroupID)
	if err != nil {
		c.log.Warnf("cannot mute cgroup %d: %v", container.CgroupID, err)
	}
}

func (c *Controller) onDeleteContainer(container *containers.Container) {
	c.resourcesStatsScrapePointsMu.Lock()
	delete(c.resourcesStatsScrapePoints, container.CgroupID)
	c.resourcesStatsScrapePointsMu.Unlock()

	c.syscallScrapePointsMu.Lock()
	delete(c.syscallScrapePoints, container.CgroupID)
	c.syscallScrapePointsMu.Unlock()

	c.dnsCache.Remove(container.CgroupID)

	c.log.Debugf("removed cgroup %d", container.CgroupID)
}

type resourcesStatsScrapePoint struct {
	ts       time.Time
	cpuStat  *cgroup.CPUStat
	memStats *cgroup.MemoryStat
	netStats *netstats.InterfaceStats
}

type syscallScrapePoint struct {
	syscalls map[ebpftracer.SyscallID]uint64
}

func (c *Controller) MuteNamespace(namespace string) error {
	c.mutedNamespacesMu.Lock()
	c.mutedNamespaces[namespace] = struct{}{}
	c.mutedNamespacesMu.Unlock()

	cgroups := c.containersClient.GetCgroupsInNamespace(namespace)

	err := c.tracer.MuteEventsFromCgroups(cgroups)

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
