package containers

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/castai/kvisor/pkg/cgroup"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/api/services/tasks/v1"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/images"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/samber/lo"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	criapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

func TestSortManifests(t *testing.T) {
	index := ocispec.Index{
		Manifests: []ocispec.Descriptor{
			{
				Platform: &ocispec.Platform{
					Architecture: "arm64",
				},
			},
			{
				Platform: &ocispec.Platform{
					Architecture: "rest",
				},
			},
			{
				Platform: &ocispec.Platform{
					Architecture: "arm64",
					Variant:      "v8",
				},
			},
			{
				Platform: &ocispec.Platform{
					Architecture: "amd64",
				},
			},
		},
	}

	sortIndexManifests(&index)

	sorted := lo.Map(index.Manifests, func(item ocispec.Descriptor, index int) string {
		return item.Platform.Architecture + item.Platform.Variant
	})

	require.Equal(t, []string{"amd64", "arm64v8", "arm64", "rest"}, sorted)
}

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
				Image: &criapi.ImageSpec{
					Image: "img1",
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

		client.containerdClient.(*mockContainerdClient).images = map[string]containerd.Image{
			"img1": containerd.NewImage(&containerd.Client{}, images.Image{
				Target: ocispec.Descriptor{
					Digest: "index-manifest-digest",
				},
			}),
		}

		client.containerContentStoreClient.(*mockContainerContentStoreClient).files = map[string]*contentStoreFile{
			"index-manifest-digest": {
				data: []byte(`
{
  "manifests": [
    {
      "digest": "sha256:83a4745a9c165dd4da61a49ddb76550909859bf6ed62d41974e31559eec7fb8e",
      "platform": {
        "architecture": "unknown",
        "os": "unknown"
      }
    },
    {
      "digest": "sha256:eafc1edb577d2e9b458664a15f23ea1c370214193226069eb22921169fc7e43f",
      "platform": {
        "architecture": "amd64",
        "os": "linux"
      }
    }
  ]
}
`),
			},
			"sha256:eafc1edb577d2e9b458664a15f23ea1c370214193226069eb22921169fc7e43f": {
				data: []byte(`
{
  "digest": "sha256:eafc1edb577d2e9b458664a15f23ea1c370214193226069eb22921169fc7e43f"
}
`),
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
		r.Equal("sha256:eafc1edb577d2e9b458664a15f23ea1c370214193226069eb22921169fc7e43f", c1.ImageDigest.String())
	})

	t.Run("load containers and merge to cached containers", func(t *testing.T) {
		r := require.New(t)
		client := newTestClient()
		client.criRuntimeServiceClient.(*mockCriClient).containers = []*criapi.Container{
			{
				Id: "c2",
				Image: &criapi.ImageSpec{
					Image: "image",
				},
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
		log:                         logging.NewTestLog(),
		criRuntimeServiceClient:     &mockCriClient{},
		cgroupClient:                &mockCgroupClient{},
		containersByID:              map[string]*Container{},
		containersByCgroup:          map[uint64]*Container{},
		inactiveContainersDuration:  1 * time.Minute,
		containerdClient:            &mockContainerdClient{},
		containerContentStoreClient: &mockContainerContentStoreClient{},
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

type mockContainerdClient struct {
	images map[string]containerd.Image
}

func (m *mockContainerdClient) GetImage(ctx context.Context, ref string) (containerd.Image, error) {
	img, found := m.images[ref]
	if !found {
		return nil, fmt.Errorf("image %s not found", ref)
	}
	return img, nil
}

func (m *mockContainerdClient) Close() error {
	return nil
}

func (m *mockContainerdClient) TaskService() tasks.TasksClient {
	return nil
}

type mockContainerContentStoreClient struct {
	files map[string]*contentStoreFile
}

func (m *mockContainerContentStoreClient) ReaderAt(ctx context.Context, desc ocispec.Descriptor) (content.ReaderAt, error) {
	if f, found := m.files[desc.Digest.String()]; found {
		return f, nil
	}
	return nil, fmt.Errorf("file %s not found", desc.Digest)
}

type contentStoreFile struct {
	data []byte
}

func (m *contentStoreFile) ReadAt(p []byte, off int64) (n int, err error) {
	copy(p, m.data[off:])
	return len(p), nil
}

func (m *contentStoreFile) Close() error {
	return nil
}

func (m *contentStoreFile) Size() int64 {
	return int64(len(m.data))
}
