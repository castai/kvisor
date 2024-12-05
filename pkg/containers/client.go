package containers

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/castai/kvisor/pkg/cgroup"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/castai/kvisor/pkg/metrics"
	"github.com/castai/kvisor/pkg/proc"
	containerdContainers "github.com/containerd/containerd/containers"
	"github.com/samber/lo"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	criapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

var (
	ErrContainerNotFound = errors.New("container not found")
)

type ContainerCreatedListener func(c *Container)
type ContainerDeletedListener func(c *Container)

type Container struct {
	ID           string
	Name         string
	CgroupID     uint64
	PodNamespace string
	PodUID       string
	PodName      string
	Cgroup       *cgroup.Cgroup
	PIDs         []uint32
	Err          error

	Labels      map[string]string
	Annotations map[string]string
}

// Client is generic container client.
type Client struct {
	log                     *logging.Logger
	containerClient         *containerClient
	cgroupClient            *cgroup.Client
	criRuntimeServiceClient criapi.RuntimeServiceClient

	containersByCgroup map[uint64]*Container
	mu                 sync.RWMutex

	containerCreatedListeners []ContainerCreatedListener
	containerDeletedListeners []ContainerDeletedListener
	listenerMu                sync.RWMutex

	procHandler *proc.Proc

	forwardedLabels      []string
	forwardedAnnotations []string
}

func NewClient(log *logging.Logger, cgroupClient *cgroup.Client, containerdSock string, procHandler *proc.Proc, criRuntimeServiceClient criapi.RuntimeServiceClient,
	labels, annotations []string) (*Client, error) {
	contClient, err := newContainerClient(containerdSock)
	if err != nil {
		return nil, err
	}

	return &Client{
		log:                     log.WithField("component", "cgroups"),
		containerClient:         contClient,
		cgroupClient:            cgroupClient,
		containersByCgroup:      map[uint64]*Container{},
		procHandler:             procHandler,
		criRuntimeServiceClient: criRuntimeServiceClient,
		forwardedLabels:         labels,
		forwardedAnnotations:    annotations,
	}, nil
}

func (c *Client) Close() error {
	return c.containerClient.client.Close()
}

type ContainerProcess struct {
	ContainerID string
	PID         uint32
}

func (c *Client) LoadContainerTasks(ctx context.Context) ([]ContainerProcess, error) {
	resp, err := c.containerClient.client.TaskService().List(ctx, nil)
	if err != nil {
		return nil, err
	}

	result := make([]ContainerProcess, 0, len(resp.Tasks))

	for _, task := range resp.Tasks {
		path, err := c.procHandler.FindCGroupPathForPID(task.Pid)
		if err != nil {
			c.log.Warnf("cannot find cgroup for PID %d: %v", task.Pid, err)
			continue
		}

		containerID, runtime := cgroup.GetContainerIdFromCgroup(path)
		if runtime != cgroup.ContainerdRuntime && runtime != cgroup.DockerRuntime {
			// We only support containerd and docker, we ignore the rest.
			continue
		}

		result = append(result, ContainerProcess{
			ContainerID: containerID,
			PID:         task.Pid,
		})
	}

	return result, nil
}

func (c *Client) ListContainers() []*Container {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return lo.Filter(lo.Values(c.containersByCgroup), func(item *Container, index int) bool {
		return item.Err == nil && item.Cgroup != nil
	})
}

func (c *Client) AddContainerByCgroupID(ctx context.Context, cgroupID cgroup.ID) (cont *Container, rerrr error) {
	defer func() {
		if rerrr != nil {
			// TODO: This is quick fix to prevent constant search for invalid containers.
			// Check for some better error handling. For example container client network error could occur.
			cont = &Container{
				Err: rerrr,
			}
			c.mu.Lock()
			c.containersByCgroup[cgroupID] = cont
			c.mu.Unlock()
		}
	}()

	cg, err := c.cgroupClient.GetCgroupForID(cgroupID)
	// The found cgroup is not a container.
	if err != nil || cg.ContainerID == "" {
		return nil, ErrContainerNotFound
	}

	container, err := c.containerClient.client.ContainerService().Get(ctx, cg.ContainerID)
	if err != nil {
		return nil, err
	}

	return c.addContainerWithCgroup(container, cg)
}

func (c *Client) addContainerWithCgroup(container containerdContainers.Container, cg *cgroup.Cgroup) (cont *Container, rerrr error) {
	podNamespace := container.Labels["io.kubernetes.pod.namespace"]
	containerName := container.Labels["io.kubernetes.container.name"]
	podName := container.Labels["io.kubernetes.pod.name"]
	podID := container.Labels["io.kubernetes.pod.uid"]

	// Only containerd is supported right now.
	// TODO: We also allow docker here, but support only docker shim. If container type docker we assume that it's still uses containerd.
	if cg.ContainerRuntime != cgroup.ContainerdRuntime && cg.ContainerRuntime != cgroup.DockerRuntime {
		return nil, ErrContainerNotFound
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	pids, err := c.containerClient.getContainerPids(ctx, cg.ContainerID)
	if err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			return nil, ErrContainerNotFound
		}
		return nil, fmt.Errorf("get container pids: %w", err)
	}

	cont = &Container{
		ID:           cg.ContainerID,
		Name:         containerName,
		CgroupID:     cg.Id,
		PodNamespace: podNamespace,
		PodUID:       podID,
		PodName:      podName,
		Cgroup:       cg,
		PIDs:         pids,
	}

	sandbox, err := c.criRuntimeServiceClient.ListPodSandbox(ctx, &criapi.ListPodSandboxRequest{
		Filter: &criapi.PodSandboxFilter{
			Id: container.SandboxID,
		},
	})

	if err != nil {
		return nil, err
	}

	if len(sandbox.Items) > 0 {
		for k, v := range sandbox.Items[0].Labels {
			for _, labelPrefix := range c.forwardedLabels {
				if strings.HasPrefix(k, labelPrefix) {
					if cont.Labels == nil {
						cont.Labels = make(map[string]string)
					}
					cont.Labels[k] = v
				}
			}
		}

		for k, v := range sandbox.Items[0].Annotations {
			for _, annotationPrefix := range c.forwardedAnnotations {
				if strings.HasPrefix(k, annotationPrefix) {
					if cont.Annotations == nil {
						cont.Annotations = make(map[string]string)
					}
					cont.Annotations[k] = v
				}
			}
		}
	} else {
		c.log.Errorf("sandbox id not found : %s", container.SandboxID)
	}

	c.mu.Lock()
	c.containersByCgroup[cg.Id] = cont
	c.mu.Unlock()

	c.log.Debugf("added container, id=%s pod=%s name=%s", container.ID, podName, containerName)

	go c.fireContainerCreatedListeners(cont)

	return cont, nil
}

func (c *Client) GetContainerForCgroup(ctx context.Context, cgroup uint64) (*Container, error) {
	container, found, err := c.LookupContainerForCgroupInCache(cgroup)
	if err != nil {
		return nil, err
	}

	if !found {
		metrics.AgentLoadContainerByCgroup.Inc()
		return c.AddContainerByCgroupID(ctx, cgroup)
	}

	return container, nil
}

func (c *Client) LookupContainerForCgroupInCache(cgroup uint64) (*Container, bool, error) {
	c.mu.RLock()
	container, found := c.containersByCgroup[cgroup]
	c.mu.RUnlock()

	if !found {
		return nil, false, nil
	}

	if container.Err != nil {
		return nil, true, container.Err
	}

	return container, true, nil
}

func (c *Client) CleanupCgroup(cgroup cgroup.ID) {
	c.mu.Lock()
	container := c.containersByCgroup[cgroup]
	delete(c.containersByCgroup, cgroup)
	c.mu.Unlock()

	if container != nil {
		c.fireContainerDeletedListeners(container)
	}
}

func (c *Client) GetCgroupsInNamespace(namespace string) []uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var result []uint64

	for cgroup, container := range c.containersByCgroup {
		if container.PodNamespace == namespace {
			result = append(result, cgroup)
		}
	}

	return result
}

func (c *Client) RegisterContainerCreatedListener(l ContainerCreatedListener) {
	c.listenerMu.Lock()
	defer c.listenerMu.Unlock()

	c.containerCreatedListeners = append(c.containerCreatedListeners, l)
}

func (c *Client) RegisterContainerDeletedListener(l ContainerDeletedListener) {
	c.listenerMu.Lock()
	defer c.listenerMu.Unlock()

	c.containerDeletedListeners = append(c.containerDeletedListeners, l)
}

func (c *Client) fireContainerCreatedListeners(container *Container) {
	c.listenerMu.RLock()
	listeners := c.containerCreatedListeners
	c.listenerMu.RUnlock()

	for _, l := range listeners {
		l(container)
	}
}

func (c *Client) fireContainerDeletedListeners(container *Container) {
	c.listenerMu.RLock()
	listeners := c.containerDeletedListeners
	c.listenerMu.RUnlock()

	for _, l := range listeners {
		l(container)
	}
}

func (c *Client) GetCgroupCpuStats(cont *Container) (*cgroup.CPUStat, error) {
	return cont.Cgroup.CpuStat()
}

func (c *Client) GetCgroupMemoryStats(cont *Container) (*cgroup.MemoryStat, error) {
	return cont.Cgroup.MemoryStat()
}
