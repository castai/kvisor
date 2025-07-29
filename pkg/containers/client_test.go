package containers

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/castai/kvisor/pkg/cgroup"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	criapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

func TestClient(t *testing.T) {
	ctx := context.Background()

	t.Run("load containers from container runtime", func(t *testing.T) {
		r := require.New(t)
		client := newTestClient()
		client.forwardedLabels = []string{"k8s-label"}
		client.forwardedAnnotations = []string{"k8s-annotation"}
		client.criRuntimeServiceClient.(*mockCriClient).containers = []*criapi.Container{
			{
				Id:           "c1",
				PodSandboxId: "p1",
				Labels: map[string]string{
					"io.kubernetes.pod.namespace":  "ns1",
					"io.kubernetes.pod.name":       "pod",
					"io.kubernetes.pod.uid":        "pod1",
					"io.kubernetes.container.name": "cont",
				},
			},
		}
		client.criRuntimeServiceClient.(*mockCriClient).sandboxes = map[string]*criapi.PodSandbox{
			"p1": {
				Id:        "p1",
				Metadata:  nil,
				State:     0,
				CreatedAt: 0,
				Labels: map[string]string{
					"k8s-label": "k8s-label-val",
				},
				Annotations: map[string]string{
					"k8s-annotation": "k8s-annotation-val",
				},
				RuntimeHandler: "",
			},
		}
		client.cgroupClient.(*mockCgroupClient).cgroupsByID = map[cgroup.ID]*cgroup.Cgroup{
			1: {
				Id:               1,
				ContainerRuntime: cgroup.ContainerdRuntime,
				ContainerID:      "c1",
				Path:             "/cgroup/c1",
			},
		}

		err := client.LoadContainers(ctx)
		r.NoError(err)

		cachedContainers := client.ListContainers(func(c *Container) bool {
			return true
		})
		r.Len(cachedContainers, 1)
		c1 := cachedContainers[0]
		r.Equal("c1", c1.ID)
		r.Equal(1, int(c1.CgroupID))
		r.Equal("pod", c1.PodName)
		r.Equal("pod1", c1.PodUID)
		r.Equal("ns1", c1.PodNamespace)
		r.Equal("cont", c1.Name)
		r.Equal("k8s-label-val", c1.Labels["k8s-label"])
		r.Equal("k8s-annotation-val", c1.Annotations["k8s-annotation"])
	})

	t.Run("load containers and merge to cached containers", func(t *testing.T) {
		r := require.New(t)
		client := newTestClient()
		client.criRuntimeServiceClient.(*mockCriClient).containers = []*criapi.Container{
			{
				Id: "c2",
			},
		}
		client.cgroupClient.(*mockCgroupClient).cgroupsByID = map[cgroup.ID]*cgroup.Cgroup{
			2: {
				Id:               2,
				ContainerRuntime: cgroup.ContainerdRuntime,
				ContainerID:      "c2",
				Path:             "/cgroup/c2",
			},
		}

		existingCont := &Container{
			ID:                    "c1",
			CgroupID:              1,
			lastAccessTimeSeconds: &atomic.Int64{},
		}
		existingCont.markAccessed()
		client.containersByCgroup = map[cgroup.ID]*Container{
			1: existingCont,
		}
		client.containersByID["c1"] = existingCont

		err := client.LoadContainers(ctx)
		r.NoError(err)

		cachedContainers := client.ListContainers(func(c *Container) bool {
			return true
		})
		r.Len(cachedContainers, 2)
		//c1 := cachedContainers[0]
		//r.Equal("c1", c1.ID)
		//r.Equal(1, int(c1.CgroupID))
		//r.Equal("pod", c1.PodName)
		//r.Equal("pod1", c1.PodUID)
		//r.Equal("ns1", c1.PodNamespace)
		//r.Equal("cont", c1.Name)
		//r.Equal("k8s-label-val", c1.Labels["k8s-label"])
		//r.Equal("k8s-annotation-val", c1.Annotations["k8s-annotation"])
	})

	t.Run("deleting inactive containers during containers load", func(t *testing.T) {
		r := require.New(t)
		client := newTestClient()
		client.inactiveContainersDuration = time.Minute

		existingCont1 := &Container{
			ID:                    "c1",
			CgroupID:              1,
			lastAccessTimeSeconds: &atomic.Int64{},
		}
		existingCont1.markAccessed()

		existingCont2 := &Container{
			ID:                    "c2",
			CgroupID:              2,
			lastAccessTimeSeconds: &atomic.Int64{},
		}
		existingCont2.lastAccessTimeSeconds.Store(time.Now().Add(-time.Hour).Unix())

		client.containersByCgroup = map[cgroup.ID]*Container{
			1: existingCont1,
			2: existingCont2,
		}
		client.containersByID["c1"] = existingCont1
		client.containersByID["c2"] = existingCont2

		err := client.LoadContainers(ctx)
		r.NoError(err)

		cachedContainers := client.ListContainers(func(c *Container) bool {
			return true
		})
		r.Len(cachedContainers, 1)
		c1 := cachedContainers[0]
		r.Equal("c1", c1.ID)
	})
}

func newTestClient() *Client {
	return &Client{
		log:                        logging.NewTestLog(),
		criRuntimeServiceClient:    &mockCriClient{},
		cgroupClient:               &mockCgroupClient{},
		containersByID:             map[string]*Container{},
		containersByCgroup:         map[uint64]*Container{},
		inactiveContainersDuration: 1 * time.Minute,
	}
}

type mockCriClient struct {
	sandboxes  map[string]*criapi.PodSandbox
	containers []*criapi.Container
}

func (m *mockCriClient) ListPodSandbox(ctx context.Context, in *criapi.ListPodSandboxRequest, opts ...grpc.CallOption) (*criapi.ListPodSandboxResponse, error) {
	if s, found := m.sandboxes[in.Filter.Id]; found {
		return &criapi.ListPodSandboxResponse{Items: []*criapi.PodSandbox{s}}, nil
	}
	return nil, fmt.Errorf("pod sandbox %s not found", in.Filter.Id)
}

func (m *mockCriClient) ListContainers(ctx context.Context, in *criapi.ListContainersRequest, opts ...grpc.CallOption) (*criapi.ListContainersResponse, error) {
	return &criapi.ListContainersResponse{Containers: m.containers}, nil
}

type mockCgroupClient struct {
	cgroupsByID map[cgroup.ID]*cgroup.Cgroup
}

func (m *mockCgroupClient) LoadCgroupByID(cgroupID cgroup.ID) (*cgroup.Cgroup, error) {
	if cg, found := m.cgroupsByID[cgroupID]; found {
		return cg, nil
	}
	return nil, fmt.Errorf("cgroup %d not found", cgroupID)
}

func (m *mockCgroupClient) LoadCgroupByContainerID(containerID string) (*cgroup.Cgroup, error) {
	for _, cg := range m.cgroupsByID {
		if cg.ContainerID == containerID {
			return cg, nil
		}
	}
	return nil, fmt.Errorf("cgroup by container %s not found", containerID)
}
