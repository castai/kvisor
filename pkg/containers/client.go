package containers

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/castai/kvisor/cmd/agent/daemon/metrics"
	"github.com/castai/kvisor/pkg/cgroup"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/castai/kvisor/pkg/proc"
	"github.com/containerd/containerd"
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
	Err          error

	PIDs []uint32

	Labels      map[string]string
	Annotations map[string]string
}

// Client is generic container client.
type Client struct {
	log                     *logging.Logger
	containerdClient        *containerd.Client
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

	containerdClient, err := containerd.New(containerdSock, containerd.WithTimeout(10*time.Second), containerd.WithDefaultNamespace("k8s.io"))
	if err != nil {
		return nil, err
	}

	return &Client{
		log:                     log.WithField("component", "cgroups"),
		containerdClient:        containerdClient,
		cgroupClient:            cgroupClient,
		containersByCgroup:      map[uint64]*Container{},
		procHandler:             procHandler,
		criRuntimeServiceClient: criRuntimeServiceClient,
		forwardedLabels:         labels,
		forwardedAnnotations:    annotations,
	}, nil
}

func (c *Client) Close() error {
	return c.containerdClient.Close()
}

type ContainerProcess struct {
	ContainerID string
	PID         uint32
}

func (c *Client) LoadContainerTasks(ctx context.Context) ([]ContainerProcess, error) {
	resp, err := c.containerdClient.TaskService().List(ctx, nil)
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

func (c *Client) LoadContainers(ctx context.Context) error {
	containersList, err := c.criRuntimeServiceClient.ListContainers(ctx, &criapi.ListContainersRequest{
		Filter: &criapi.ContainerFilter{
			State: &criapi.ContainerStateValue{
				State: criapi.ContainerState_CONTAINER_RUNNING,
			},
		},
	})
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.containersByCgroup = map[uint64]*Container{}
	c.mu.Unlock()

	var added int
	for _, container := range containersList.Containers {
		err = c.addContainer(container)
		if err != nil {
			c.log.Warnf("adding container, state=%v %v %v: %v", container.State, container.Id, container.Labels, err)
			continue
		}
		added++
	}
	c.log.Debugf("loaded %d containers out of %d", added, len(containersList.Containers))
	return nil
}

func (c *Client) ListContainers() []*Container {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var res []*Container
	for _, cont := range c.containersByCgroup {
		if cont.Err != nil || cont.Cgroup == nil || cont.Name == "" {
			continue
		}
		res = append(res, cont)
	}
	return res
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

	cg, err := c.cgroupClient.GetCgroupByID(cgroupID)
	// The found cgroup is not a container.
	if err != nil || cg.ContainerID == "" {
		return nil, ErrContainerNotFound
	}

	resp, err := c.criRuntimeServiceClient.ListContainers(ctx, &criapi.ListContainersRequest{
		Filter: &criapi.ContainerFilter{
			Id: cg.ContainerID,
		},
	})
	if err != nil {
		return nil, err
	}
	if len(resp.Containers) == 0 {
		return nil, ErrContainerNotFound
	}

	if len(resp.Containers) > 1 {
		return nil, fmt.Errorf("multiple containers found when one was expected")
	}

	return c.addContainerWithCgroup(resp.Containers[0], cg)
}

func (c *Client) addContainer(cont *criapi.Container) error {
	cg, err := c.cgroupClient.GetCgroupByContainerID(cont.Id)
	if err != nil || cg.ContainerID == "" {
		if errors.Is(err, cgroup.ErrCgroupNotFound) {
			return ErrContainerNotFound
		}
		return err
	}
	_, err = c.addContainerWithCgroup(cont, cg)
	return err
}

func (c *Client) addContainerWithCgroup(container *criapi.Container, cg *cgroup.Cgroup) (cont *Container, rerrr error) {
	podNamespace := container.Labels["io.kubernetes.pod.namespace"]
	containerName := container.Labels["io.kubernetes.container.name"]
	podName := container.Labels["io.kubernetes.pod.name"]
	podID := container.Labels["io.kubernetes.pod.uid"]

	// Only containerd is supported right now.
	// TODO: We also allow docker here, but support only docker shim. If container type docker we assume that it's still uses containerd.
	if cg.ContainerRuntime != cgroup.ContainerdRuntime && cg.ContainerRuntime != cgroup.DockerRuntime {
		return nil, fmt.Errorf("invalid container runtime %v", cg.ContainerRuntime)
	}

	cont = &Container{
		ID:           cg.ContainerID,
		Name:         containerName,
		CgroupID:     cg.Id,
		PodNamespace: podNamespace,
		PodUID:       podID,
		PodName:      podName,
		Cgroup:       cg,
	}

	getSandboxCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	sandbox, err := c.getPodSandbox(getSandboxCtx, container)
	if err != nil {
		c.log.Warnf("cannot get pod sandbox: %v", err)
	}

	if sandbox != nil {
		for k, v := range sandbox.Labels {
			for _, labelPrefix := range c.forwardedLabels {
				if strings.HasPrefix(k, labelPrefix) {
					if cont.Labels == nil {
						cont.Labels = make(map[string]string)
					}
					cont.Labels[k] = v
				}
			}
		}

		for k, v := range sandbox.Annotations {
			for _, annotationPrefix := range c.forwardedAnnotations {
				if strings.HasPrefix(k, annotationPrefix) {
					if cont.Annotations == nil {
						cont.Annotations = make(map[string]string)
					}
					cont.Annotations[k] = v
				}
			}
		}
	}

	c.mu.Lock()
	c.containersByCgroup[cg.Id] = cont
	c.mu.Unlock()

	c.log.Debugf("added container, id=%s pod=%s name=%s sandbox=%s", container.Id, podName, containerName, container.PodSandboxId)

	go c.fireContainerCreatedListeners(cont)

	return cont, nil
}

func (c *Client) getPodSandbox(ctx context.Context, cont *criapi.Container) (*criapi.PodSandbox, error) {
	sandboxResp, err := c.criRuntimeServiceClient.ListPodSandbox(ctx, &criapi.ListPodSandboxRequest{
		Filter: &criapi.PodSandboxFilter{
			Id: cont.PodSandboxId,
		},
	})

	if err != nil {
		return nil, err
	}

	if len(sandboxResp.Items) == 0 {
		return nil, fmt.Errorf("pod sandbox not found: %w", err)
	}
	if len(sandboxResp.Items) > 1 {
		return nil, fmt.Errorf("multiple sandboxes found when one was expected")
	}

	return sandboxResp.Items[0], nil
}

func (c *Client) GetOrLoadContainerByCgroupID(ctx context.Context, cgroup uint64) (*Container, error) {
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

	for cg, container := range c.containersByCgroup {
		if container.PodNamespace == namespace {
			result = append(result, cg)
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

func (c *Client) GetCgroupStats(cont *Container) (cgroup.Stats, error) {
	return cont.Cgroup.GetStats()
}
