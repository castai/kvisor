package containers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/castai/kvisor/cmd/agent/daemon/metrics"
	"github.com/castai/kvisor/pkg/cgroup"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/castai/kvisor/pkg/proc"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/api/services/tasks/v1"
	"github.com/containerd/containerd/content"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials/insecure"
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

	Labels      map[string]string
	Annotations map[string]string

	lastAccessTimeSeconds *atomic.Int64
	ImageDigest           digest.Digest
}

func (c *Container) markAccessed() {
	c.lastAccessTimeSeconds.Store(time.Now().Unix())
}

type criClient interface {
	ListPodSandbox(ctx context.Context, in *criapi.ListPodSandboxRequest, opts ...grpc.CallOption) (*criapi.ListPodSandboxResponse, error)
	ListContainers(ctx context.Context, in *criapi.ListContainersRequest, opts ...grpc.CallOption) (*criapi.ListContainersResponse, error)
}

type cgroupsClient interface {
	LoadCgroupByID(cgroupID cgroup.ID) (*cgroup.Cgroup, error)
	LoadCgroupByContainerID(containerID string) (*cgroup.Cgroup, error)
}

type containerdClient interface {
	GetImage(ctx context.Context, ref string) (containerd.Image, error)
	Close() error
	TaskService() tasks.TasksClient
}

type containerContentStoreClient interface {
	ReaderAt(ctx context.Context, desc ocispec.Descriptor) (content.ReaderAt, error)
}

// Client is generic container client.
type Client struct {
	log                         *logging.Logger
	containerdClient            containerdClient
	cgroupClient                cgroupsClient
	criRuntimeServiceClient     criClient
	containerContentStoreClient containerContentStoreClient
	containerdAvailable         bool

	containerCreatedListeners []ContainerCreatedListener
	containerDeletedListeners []ContainerDeletedListener
	listenerMu                sync.RWMutex

	procHandler *proc.Proc

	forwardedLabels      []string
	forwardedAnnotations []string

	containersByID             map[string]*Container
	containersByCgroup         map[uint64]*Container
	mu                         sync.RWMutex
	inactiveContainersDuration time.Duration
}

func NewClient(log *logging.Logger, cgroupClient *cgroup.Client, containerdSock string, containerdEnabled bool, procHandler *proc.Proc, criRuntimeServiceClient criapi.RuntimeServiceClient,
	labels, annotations []string) (*Client, error) {

	client := &Client{
		log:                        log.WithField("component", "cgroups"),
		cgroupClient:               cgroupClient,
		containersByCgroup:         map[uint64]*Container{},
		containersByID:             map[string]*Container{},
		procHandler:                procHandler,
		criRuntimeServiceClient:    criRuntimeServiceClient,
		forwardedLabels:            labels,
		forwardedAnnotations:       annotations,
		inactiveContainersDuration: 2 * time.Minute,
		containerdAvailable:        containerdEnabled,
	}

	if !containerdEnabled {
		log.Info("containerd client disabled")
		return client, nil
	}

	backoffConfig := backoff.DefaultConfig
	backoffConfig.MaxDelay = 3 * time.Second
	connParams := grpc.ConnectParams{
		Backoff: backoffConfig,
	}

	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithConnectParams(connParams),
		grpc.WithNoProxy(),
	}
	containerdClient, err := containerd.New(
		containerdSock,
		containerd.WithTimeout(10*time.Second),
		containerd.WithDefaultNamespace("k8s.io"),
		containerd.WithDialOpts(dialOpts),
	)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := containerdClient.Version(ctx); err != nil {
		return nil, fmt.Errorf("failed connecting to containerd client: %w", err)
	}

	client.containerdClient = containerdClient
	client.containerContentStoreClient = containerdClient.ContentStore()

	return client, nil
}

func (c *Client) Close() error {
	if c.containerdAvailable {
		return c.containerdClient.Close()
	}
	return nil
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
	start := time.Now()
	// Load latest running containers and upsert to local containers cache.
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
	var added int
	for _, container := range containersList.Containers {
		err = c.upsertContainer(container)
		if err != nil {
			c.log.Warnf("upserting container, state=%v %v %v: %v", container.State, container.Id, container.Labels, err)
			continue
		}
		added++
	}
	c.log.Infof("loaded %d containers out of %d, duration=%v", added, len(containersList.Containers), time.Since(start))

	// Cleanup any inactive containers.
	now := time.Now().UTC()
	inactiveCachedContainers := c.ListContainers(func(cont *Container) bool {
		diff := now.Sub(time.Unix(cont.lastAccessTimeSeconds.Load(), 0).UTC())
		return diff > c.inactiveContainersDuration
	})

	if l := len(inactiveCachedContainers); l > 0 {
		for _, cont := range inactiveCachedContainers {
			c.CleanupByCgroupID(cont.CgroupID)
		}
		c.log.Debugf("removed %d inactive containers", l)
	}

	return nil
}

func (c *Client) ListContainers(filter func(c *Container) bool) []*Container {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var res []*Container
	for _, cont := range c.containersByCgroup {
		if filter(cont) {
			res = append(res, cont)
		}
	}
	return res
}

func (c *Client) AddContainerByCgroupID(ctx context.Context, cgroupID cgroup.ID) (cont *Container, rerrr error) {
	defer func() {
		if rerrr != nil {
			// TODO: This is quick fix to prevent constant search for invalid containers.
			// Check for some better error handling. For example container client network error could occur.
			cont = &Container{
				CgroupID:              cgroupID,
				Err:                   rerrr,
				lastAccessTimeSeconds: &atomic.Int64{},
			}
			cont.markAccessed()
			c.mu.Lock()
			c.containersByCgroup[cgroupID] = cont
			c.mu.Unlock()
		}
	}()

	cg, err := c.cgroupClient.LoadCgroupByID(cgroupID)
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

func (c *Client) upsertContainer(cont *criapi.Container) error {
	// Fast path. If container is already added skip loading it's cgroup and metadata.
	c.mu.RLock()
	cachedCont, found := c.containersByID[cont.Id]
	c.mu.RUnlock()
	if found && (cachedCont.Err == nil || errors.Is(cachedCont.Err, ErrContainerNotFound)) {
		cachedCont.markAccessed()
		return nil
	}

	// Find cgroup in cgroups file system and load container k8s metadata.
	cg, err := c.cgroupClient.LoadCgroupByContainerID(cont.Id)
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
		ID:                    cg.ContainerID,
		Name:                  containerName,
		CgroupID:              cg.Id,
		PodNamespace:          podNamespace,
		PodUID:                podID,
		PodName:               podName,
		Cgroup:                cg,
		lastAccessTimeSeconds: &atomic.Int64{},
	}
	cont.markAccessed()

	if c.containerdAvailable {
		imageDigest, err := c.findImageDigest(container)
		if err != nil {
			c.log.Warnf("finding image digest for container %v: %v", container.Id, err)
		}
		cont.ImageDigest = imageDigest
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
	c.containersByID[cont.ID] = cont
	c.mu.Unlock()

	c.log.Debugf("added container, cgroup=%d id=%s pod=%s name=%s sandbox=%s", cg.Id, container.Id, podName, containerName, container.PodSandboxId)

	go c.fireContainerCreatedListeners(cont)

	return cont, nil
}

// findImageDigest tries to find actual image digest based on config file or manifest.
// Image digest on the container can point to index manifest digest.
func (c *Client) findImageDigest(container *criapi.Container) (digest.Digest, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dig := container.ImageId
	if dig == "" {
		dig = container.Image.Image
	}

	// Fetch image details.
	img, err := c.containerdClient.GetImage(ctx, dig)
	if err != nil {
		return "", err
	}
	imageDigest := img.Target().Digest

	// Check if this digest points to index manifest. If it doesn't we can return current digest.
	imgContent, err := c.containerContentStoreClient.ReaderAt(ctx, ocispec.Descriptor{
		Digest: imageDigest,
	})
	if err != nil {
		return "", err
	}
	defer imgContent.Close()
	data, err := readAllFromReaderAt(imgContent, imgContent.Size())
	if err != nil {
		return "", err
	}
	var index ocispec.Index
	if err := json.Unmarshal(data, &index); err != nil || len(index.Manifests) == 0 {
		// If we can't parse to index, assume we already have a correct digest.
		return imageDigest, nil
	}

	// Image points to index manifest. We need to find index manifest file and
	// poke file system by each manifest in order. The first one which is found should point to actual manifest digest.
	sortIndexManifests(&index)
	for _, manifest := range index.Manifests {
		imgContent, err = c.containerContentStoreClient.ReaderAt(ctx, ocispec.Descriptor{
			Digest: manifest.Digest,
		})
		if imgContent != nil {
			imgContent.Close()
		}
		if err == nil {
			// We found actual manifest on the file system.
			return manifest.Digest, nil
		}
	}

	return "", fmt.Errorf("actual image digest not found, initial digest=%s", imageDigest)
}

func sortIndexManifests(index *ocispec.Index) {
	sortOrder := map[string]int{
		"amd64":   -4,
		"arm64v8": -3,
		"arm64v7": -2,
		"arm64":   -1,
	}
	slices.SortFunc(index.Manifests, func(a, b ocispec.Descriptor) int {
		key1, key2 := "", ""
		if a.Platform != nil {
			key1 = a.Platform.Architecture + a.Platform.Variant
		}
		if b.Platform != nil {
			key2 = b.Platform.Architecture + b.Platform.Variant
		}
		a1 := sortOrder[key1]
		b1 := sortOrder[key2]
		if a1 < b1 {
			return -1
		}
		if a1 > b1 {
			return 1
		}
		return 0
	})
}

func readAllFromReaderAt(r io.ReaderAt, size int64) ([]byte, error) {
	buf := make([]byte, size)
	_, err := r.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return buf, nil
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

func (c *Client) GetOrLoadContainerByCgroupID(ctx context.Context, cgroup uint64) (cont *Container, rerr error) {
	container, found, err := c.lookupContainerForCgroupInCache(cgroup)
	if err != nil {
		return nil, err
	}

	defer func() {
		if rerr == nil {
			cont.markAccessed()
		}
	}()

	if !found {
		metrics.AgentLoadContainerByCgroup.Inc()
		return c.AddContainerByCgroupID(ctx, cgroup)
	}

	return container, nil
}

func (c *Client) lookupContainerForCgroupInCache(cgroup uint64) (*Container, bool, error) {
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

func (c *Client) CleanupByCgroupID(cgroup cgroup.ID) {
	c.mu.Lock()
	container := c.containersByCgroup[cgroup]
	delete(c.containersByCgroup, cgroup)
	if container != nil {
		delete(c.containersByID, container.ID)
	}
	c.mu.Unlock()

	if container != nil {
		go c.fireContainerDeletedListeners(container)
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
