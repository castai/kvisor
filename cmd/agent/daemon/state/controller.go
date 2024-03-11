package state

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/castai/kvisor/cmd/agent/daemon/conntrack"
	"github.com/castai/kvisor/cmd/agent/daemon/netstats"
	"github.com/castai/kvisor/cmd/agent/kube"
	"github.com/castai/kvisor/pkg/castai"
	"github.com/castai/kvisor/pkg/cgroup"
	"github.com/castai/kvisor/pkg/ebpftracer"
	"github.com/castai/kvisor/pkg/ebpftracer/signature"
	"github.com/castai/kvisor/pkg/logging"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/containers"
)

type Config struct {
	EventsSinkQueueSize          int           `validate:"required"`
	ContainerStatsScrapeInterval time.Duration `validate:"required"`
}

func NewController(
	log *logging.Logger,
	cfg Config,
	apiClient *castai.Client,
	containersClient *containers.Client,
	netStatsReader *netstats.Reader,
	ct conntrack.Client,
	tracer *ebpftracer.Tracer,
	signatureEngine *signature.SignatureEngine,
	kubeClient *kube.Client,
) *Controller {
	return &Controller{
		log:                         log.WithField("component", "ctrl"),
		cfg:                         cfg,
		castClient:                  apiClient,
		containersClient:            containersClient,
		netStatsReader:              netStatsReader,
		ct:                          ct,
		tracer:                      tracer,
		signatureEngine:             signatureEngine,
		nodeName:                    os.Getenv("NODE_NAME"),
		eventsExportQueue:           make(chan *castpb.Event, cfg.EventsSinkQueueSize),
		resourcesStatsScrapePoints:  map[uint64]*resourcesStatsScrapePoint{},
		syscallScrapePoints:         map[uint64]*syscallScrapePoint{},
		debugEvent:                  os.Getenv("KVISORD_EBPF_DEBUG") == "1",
		writeStreamCreateRetryDelay: 2 * time.Second,
		mutedNamespaces:             map[string]struct{}{},
		kubeClient:                  kubeClient,
	}
}

type Controller struct {
	log              *logging.Logger
	cfg              Config
	castClient       *castai.Client
	containersClient *containers.Client
	netStatsReader   *netstats.Reader
	ct               conntrack.Client
	tracer           *ebpftracer.Tracer
	signatureEngine  *signature.SignatureEngine

	nodeName string

	eventsExportQueue chan *castpb.Event
	debugEvent        bool

	// Scrape points are used to calculate deltas between scrapes.
	resourcesStatsScrapePointsMu sync.RWMutex
	resourcesStatsScrapePoints   map[uint64]*resourcesStatsScrapePoint
	syscallScrapePointsMu        sync.RWMutex
	syscallScrapePoints          map[uint64]*syscallScrapePoint

	writeStreamCreateRetryDelay time.Duration

	mutedNamespacesMu sync.RWMutex
	mutedNamespaces   map[string]struct{}

	kubeClient *kube.Client
}

func (c *Controller) Run(ctx context.Context) error {
	c.log.Infof("running")
	defer c.log.Infof("stopping")

	c.containersClient.RegisterContainerCreatedListener(c.onNewContainer)
	c.containersClient.RegisterContainerDeletedListener(c.onDeleteContainer)

	var errg errgroup.Group
	errg.Go(func() error {
		return c.runEventsExportLoop(ctx)
	})
	errg.Go(func() error {
		return c.runContainerStatsPipeline(ctx)
	})
	errg.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case e := <-c.tracer.Events():
				c.handleEvent(e)
			case e := <-c.signatureEngine.Events():
				c.handleEvent(e)
			}
		}
	})

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

func isGRPCError(err error, codes ...codes.Code) bool {
	st, ok := status.FromError(err)
	if !ok {
		return false
	}
	for _, code := range codes {
		if st.Code() == code {
			return true
		}
	}
	return false
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
