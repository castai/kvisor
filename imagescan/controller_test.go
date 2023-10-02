package imagescan

import (
	"context"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/castai/kvisor/castai"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	imgcollectorconfig "github.com/castai/kvisor/cmd/imgcollector/config"
	"github.com/castai/kvisor/config"
)

func TestSubscriber(t *testing.T) {

	ctx := context.Background()
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	createNode := func(name string) *corev1.Node {
		return &corev1.Node{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Node",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
			Status: corev1.NodeStatus{
				NodeInfo: corev1.NodeSystemInfo{
					Architecture: "amd64",
				},
				Allocatable: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("2"),
					corev1.ResourceMemory: resource.MustParse("4Gi"),
				},
			},
		}
	}

	assertLoop := func(errc chan error, assertFunc func() bool) {
		timeout := time.After(2 * time.Second)

		for {
			select {
			case err := <-errc:
				t.Fatal(err)
			case <-timeout:
				t.Fatal("timeout waiting for image scan")
			case <-time.After(10 * time.Millisecond):
				if assertFunc() {
					return
				}
			}
		}
	}

	t.Run("schedule and finish scan", func(t *testing.T) {
		r := require.New(t)

		node1 := createNode("n1")
		node2 := createNode("n2")

		nginxPod1 := &corev1.Pod{
			TypeMeta: metav1.TypeMeta{Kind: "Pod", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				UID:       types.UID(uuid.New().String()),
				Name:      "nginx-1",
				Namespace: "default",
			},
			Spec: corev1.PodSpec{
				NodeName: node1.Name,
				Containers: []corev1.Container{
					{
						Name:  "nginx",
						Image: "nginx:1.23",
					},
				},
			},
			Status: corev1.PodStatus{
				Phase: corev1.PodRunning,
				ContainerStatuses: []corev1.ContainerStatus{
					{Name: "nginx", ImageID: "nginx:1.23@sha256", ContainerID: "containerd://sha256"},
				},
			},
		}

		nginxPod2 := &corev1.Pod{
			TypeMeta: metav1.TypeMeta{Kind: "Pod", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				UID:       types.UID(uuid.New().String()),
				Name:      "nginx-2",
				Namespace: "kube-system",
			},
			Spec: corev1.PodSpec{
				NodeName: node2.Name,
				Containers: []corev1.Container{
					{
						Name:  "nginx",
						Image: "nginx:1.23",
					},
				},
			},
			Status: corev1.PodStatus{
				Phase: corev1.PodRunning,
				ContainerStatuses: []corev1.ContainerStatus{
					{Name: "nginx", ImageID: "nginx:1.23@sha256", ContainerID: "containerd://sha256"},
				},
			},
		}

		argoDeployment := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				UID: types.UID(uuid.New().String()),
			},
		}

		argoReplicaSet := &appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{
				UID: types.UID(uuid.New().String()),
				OwnerReferences: []metav1.OwnerReference{
					{
						UID:        argoDeployment.UID,
						APIVersion: "apps/v1",
						Kind:       "Deployment",
						Name:       "argocd-a123",
					},
				},
			},
		}

		createArgoPod := func(podName string) *corev1.Pod {
			return &corev1.Pod{
				TypeMeta: metav1.TypeMeta{Kind: "Pod", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					UID:       types.UID(uuid.New().String()),
					Name:      podName,
					Namespace: "argo",
					OwnerReferences: []metav1.OwnerReference{
						{
							UID:        argoReplicaSet.UID,
							APIVersion: "apps/v1",
							Kind:       "ReplicaSet",
							Name:       "argocd-a123",
						},
					},
				},
				Spec: corev1.PodSpec{
					NodeName: node2.Name,
					Containers: []corev1.Container{
						{
							Name:  "argocd",
							Image: "argocd:0.0.1",
						},
					},
					InitContainers: []corev1.Container{
						{
							Name:  "init-argo",
							Image: "init-argo:0.0.1",
						},
					},
				},
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
					ContainerStatuses: []corev1.ContainerStatus{
						{Name: "argocd", ImageID: "argocd:1.23@sha256", ContainerID: "containerd://sha256"},
					},
					InitContainerStatuses: []corev1.ContainerStatus{
						{Name: "init-argo", ImageID: "init-argo:1.23@sha256", ContainerID: "containerd://sha256"},
					},
				},
			}
		}

		argoPod1 := createArgoPod("argo1")
		argoPod2 := createArgoPod("argo2")

		cfg := config.ImageScan{
			ScanInterval:       1 * time.Millisecond,
			ScanTimeout:        time.Minute,
			Mode:               "hostfs",
			MaxConcurrentScans: 5,
			CPURequest:         "500m",
			CPULimit:           "2",
			MemoryRequest:      "100Mi",
			MemoryLimit:        "2Gi",
		}

		scanner := &mockImageScanner{}
		client := &mockCastaiClient{}
		sub := NewController(log, cfg, scanner, client, 21)
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		// Simulate concurrent deltas update.
		go func() {
			for {
				sub.OnUpdate(node1)
				sub.OnUpdate(node2)
				sub.OnUpdate(argoReplicaSet)
				sub.OnUpdate(argoPod1)
				sub.OnUpdate(argoPod2)
				sub.OnUpdate(nginxPod1)
				sub.OnUpdate(nginxPod2)
				time.Sleep(1 * time.Millisecond)
			}
		}()

		errc := make(chan error, 1)
		go func() {
			errc <- sub.Run(ctx)
		}()

		assertLoop(errc, func() bool {
			imgs := scanner.getScanImageParams()
			if len(imgs) == 0 {
				return false
			}

			sort.Slice(imgs, func(i, j int) bool {
				return imgs[i].ImageName < imgs[j].ImageName
			})
			r.Len(imgs, 3)
			argoImg := imgs[0]
			argoInitImg := imgs[1]
			ngnxImage := imgs[2]
			r.Equal("argocd:0.0.1", argoImg.ImageName)
			r.Equal("init-argo:0.0.1", argoInitImg.ImageName)
			r.Equal([]string{string(argoDeployment.UID)}, argoImg.ResourceIDs)

			actualNginxPodResourceIDs := []string{string(nginxPod1.UID), string(nginxPod2.UID)}
			sort.Strings(ngnxImage.ResourceIDs)
			sort.Strings(actualNginxPodResourceIDs)
			r.Equal(ngnxImage.ResourceIDs, actualNginxPodResourceIDs)
			r.NotEmpty(ngnxImage.NodeName)
			r.Equal(ScanImageParams{
				ImageName:                   "nginx:1.23",
				ImageID:                     "nginx:1.23@sha256",
				ContainerRuntime:            "containerd",
				Mode:                        "hostfs",
				NodeName:                    ngnxImage.NodeName,
				ResourceIDs:                 ngnxImage.ResourceIDs,
				DeleteFinishedJob:           true,
				WaitForCompletion:           true,
				WaitDurationAfterCompletion: 30 * time.Second,
			}, ngnxImage)

			return true
		})

	})

	t.Run("retry failed images", func(t *testing.T) {
		r := require.New(t)

		cfg := config.ImageScan{
			ScanInterval:       1 * time.Millisecond,
			ScanTimeout:        time.Minute,
			MaxConcurrentScans: 5,
			CPURequest:         "500m",
			CPULimit:           "2",
			MemoryRequest:      "100Mi",
			MemoryLimit:        "2Gi",
		}

		scanner := &mockImageScanner{}
		client := &mockCastaiClient{}
		sub := NewController(log, cfg, scanner, client, 21)
		sub.timeGetter = func() time.Time {
			return time.Now().UTC().Add(time.Hour)
		}
		delta := sub.delta
		img := newImage("img1", "amd64")
		img.name = "img"
		img.nodes = map[string]*imageNode{
			"node1": {},
		}
		img.owners = map[string]*imageOwner{
			"r1": {},
		}
		delta.images[img.cacheKey()] = img
		delta.setImageScanError(img, errors.New("failed"))
		delta.setImageScanError(img, errors.New("failed again"))

		resMem := resource.MustParse("500Mi")
		resCpu := resource.MustParse("2")
		delta.nodes["node1"] = &node{
			name:           "node1",
			allocatableMem: resMem.AsDec(),
			allocatableCPU: resCpu.AsDec(),
			pods:           map[types.UID]*pod{},
		}

		ctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		defer cancel()

		errc := make(chan error, 1)
		go func() {
			errc <- sub.Run(ctx)
		}()

		assertLoop(errc, func() bool {
			imgs := scanner.getScanImageParams()
			if len(imgs) == 0 {
				return false
			}

			r.Len(imgs, 1)
			img = delta.images[img.cacheKey()]
			r.False(img.nextScan.IsZero())
			r.True(img.scanned)
			return true
		})
	})

	t.Run("scan image with remote mode fallback", func(t *testing.T) {
		r := require.New(t)

		cfg := config.ImageScan{
			ScanInterval:       1 * time.Millisecond,
			ScanTimeout:        time.Minute,
			MaxConcurrentScans: 5,
			Mode:               string(imgcollectorconfig.ModeHostFS),
			CPURequest:         "500m",
			CPULimit:           "2",
			MemoryRequest:      "100Mi",
			MemoryLimit:        "2Gi",
		}

		scanner := &mockImageScanner{}
		client := &mockCastaiClient{}
		sub := NewController(log, cfg, scanner, client, 21)
		sub.timeGetter = func() time.Time {
			return time.Now().UTC().Add(time.Hour)
		}
		delta := sub.delta
		img := newImage("img1", "amd64")
		img.name = "img"
		img.containerRuntime = imgcollectorconfig.RuntimeContainerd
		img.nodes = map[string]*imageNode{
			"node1": {},
		}
		img.owners = map[string]*imageOwner{
			"r1": {},
		}
		delta.images[img.cacheKey()] = img
		delta.setImageScanError(img, errImageScanLayerNotFound)

		resMem := resource.MustParse("500Mi")
		resCpu := resource.MustParse("2")
		delta.nodes["node1"] = &node{
			name:           "node1",
			allocatableMem: resMem.AsDec(),
			allocatableCPU: resCpu.AsDec(),
			pods:           map[types.UID]*pod{},
		}

		ctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		defer cancel()

		errc := make(chan error, 1)
		go func() {
			errc <- sub.Run(ctx)
		}()

		assertLoop(errc, func() bool {
			imgs := scanner.getScanImageParams()
			if len(imgs) == 0 {
				return false
			}

			r.Len(imgs, 1)
			r.Equal(string(imgcollectorconfig.ModeRemote), imgs[0].Mode)
			return true
		})
	})

	t.Run("select any node with remote scan mode", func(t *testing.T) {
		r := require.New(t)

		cfg := config.ImageScan{
			ScanInterval:       1 * time.Millisecond,
			ScanTimeout:        time.Minute,
			MaxConcurrentScans: 5,
			Mode:               string(imgcollectorconfig.ModeRemote),
			CPURequest:         "500m",
			CPULimit:           "2",
			MemoryRequest:      "100Mi",
			MemoryLimit:        "2Gi",
		}

		scanner := &mockImageScanner{}
		client := &mockCastaiClient{}
		sub := NewController(log, cfg, scanner, client, 21)
		sub.timeGetter = func() time.Time {
			return time.Now().UTC().Add(time.Hour)
		}
		delta := sub.delta
		img := newImage("img1", "amd64")
		img.name = "img"
		img.containerRuntime = imgcollectorconfig.RuntimeContainerd
		img.owners = map[string]*imageOwner{
			"r1": {},
		}
		delta.images[img.cacheKey()] = img

		resMem := resource.MustParse("500Mi")
		resCpu := resource.MustParse("2")
		delta.nodes["node1"] = &node{
			name:           "node1",
			allocatableMem: resMem.AsDec(),
			allocatableCPU: resCpu.AsDec(),
			pods:           map[types.UID]*pod{},
		}

		ctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		defer cancel()

		errc := make(chan error, 1)
		go func() {
			errc <- sub.Run(ctx)
		}()

		assertLoop(errc, func() bool {
			imgs := scanner.getScanImageParams()
			if len(imgs) == 0 {
				return false
			}

			r.Len(imgs, 1)
			r.Equal(string(imgcollectorconfig.ModeRemote), imgs[0].Mode)
			return true
		})
	})

	t.Run("respect node count", func(t *testing.T) {
		r := require.New(t)

		cfg := config.ImageScan{
			ScanInterval:       1 * time.Millisecond,
			ScanTimeout:        time.Minute,
			MaxConcurrentScans: 5,
			CPURequest:         "500m",
			CPULimit:           "2",
			MemoryRequest:      "100Mi",
			MemoryLimit:        "2Gi",
			Mode:               string(imgcollectorconfig.ModeHostFS),
		}

		client := &mockCastaiClient{}
		scanner := &mockImageScanner{}
		sub := NewController(log, cfg, scanner, client, 21)
		delta := sub.delta
		delta.images["img1"] = &image{
			name: "img",
			id:   "img1",
			nodes: map[string]*imageNode{
				"node1": {},
			},
			owners: map[string]*imageOwner{
				"r1": {},
			},
		}

		firstCtx, firstCancel := context.WithTimeout(ctx, 50*time.Millisecond)
		defer firstCancel()

		err := sub.scheduleScans(firstCtx)
		r.NoError(err)
		// without nodes in delta it should not schedule scan.
		r.Len(scanner.imgs, 0)

		resMem := resource.MustParse("500Mi")
		resCpu := resource.MustParse("2")
		// with two nodes it should scan without resource check.
		delta.nodes["test_a"] = &node{}
		delta.nodes["node1"] = &node{
			name:           "node1",
			allocatableMem: resMem.AsDec(),
			allocatableCPU: resCpu.AsDec(),
			pods:           map[types.UID]*pod{},
		}
		delta.images["img1"] = &image{
			name: "img",
			id:   "img1",
			nodes: map[string]*imageNode{
				"node1": {},
			},
			owners: map[string]*imageOwner{
				"r1": {},
			},
		}

		secondCtx, secondCancel := context.WithTimeout(ctx, 50*time.Millisecond)
		defer secondCancel()

		err = sub.scheduleScans(secondCtx)
		r.NoError(err)
		r.Len(scanner.imgs, 1)
		r.True(delta.images["img1"].scanned)
	})

	t.Run("send changed resource owners", func(t *testing.T) {
		r := require.New(t)

		cfg := config.ImageScan{
			ScanInterval: 1 * time.Millisecond,
		}

		scanner := &mockImageScanner{}
		client := &mockCastaiClient{}
		sub := NewController(log, cfg, scanner, client, 21)
		sub.timeGetter = func() time.Time {
			return time.Now().UTC().Add(time.Hour)
		}
		delta := sub.delta
		img := newImage("img1", "amd64")
		img.name = "img"
		img.owners = map[string]*imageOwner{
			"r1": {},
		}
		img.ownerChanges = ownerChanges{
			addedIDS:   []string{"r1"},
			removedIDs: []string{"r2"},
		}
		delta.images[img.cacheKey()] = img

		ctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		defer cancel()

		errc := make(chan error, 1)
		go func() {
			errc <- sub.Run(ctx)
		}()

		assertLoop(errc, func() bool {
			changes := client.getImagesResourcesChanges()
			if len(changes) < 2 {
				return false
			}

			// Should have only 2 calls to api.
			r.Len(changes, 2)

			// First api call. Initial full resync.
			change1Img1 := changes[0].Images[0]
			r.Equal("img1", change1Img1.ID)
			r.Equal("amd64", change1Img1.Architecture)
			r.Equal([]string{"r1"}, change1Img1.ResourcesChange.ResourceIDs)
			r.True(img.ownerChanges.empty())

			// Second api call. Only image owner change.
			change2Img1 := changes[1].Images[0]
			r.Equal("img1", change2Img1.ID)
			r.Equal("amd64", change2Img1.Architecture)
			r.Equal([]string{"r1"}, change2Img1.ResourcesChange.ResourceIDs)
			r.Equal([]string{"r2"}, change2Img1.ResourcesChange.RemovedResourceIDs)

			return true
		})
	})

	t.Run("sync scanned images from remote state", func(t *testing.T) {
		r := require.New(t)

		cfg := config.ImageScan{
			ScanInterval:       1 * time.Millisecond,
			ScanTimeout:        time.Minute,
			MaxConcurrentScans: 5,
			CPURequest:         "500m",
			CPULimit:           "2",
			MemoryRequest:      "100Mi",
			MemoryLimit:        "2Gi",
		}

		scanner := &mockImageScanner{}
		client := &mockCastaiClient{
			syncState: &castai.SyncStateResponse{
				Images: &castai.ImagesSyncState{
					ScannedImages: []castai.ScannedImage{
						{
							ID:           "img1",
							Architecture: "amd64",
						},
						{
							ID:           "img2",
							Architecture: "amd64",
						},
					},
				},
			},
		}
		sub := NewController(log, cfg, scanner, client, 21)
		sub.timeGetter = func() time.Time {
			return time.Now().UTC().Add(time.Hour)
		}
		delta := sub.delta
		img1 := newImage("img1", "amd64")
		img1.name = "img1"
		img1.owners = map[string]*imageOwner{
			"r1": {},
		}
		delta.images[img1.cacheKey()] = img1

		img2 := newImage("img2", "amd64")
		img2.name = "img2"
		img2.owners = map[string]*imageOwner{
			"r2": {},
		}
		delta.images[img2.cacheKey()] = img2

		errc := make(chan error, 1)
		go func() {
			errc <- sub.Run(ctx)
		}()

		assertLoop(errc, func() bool {
			syncCalls := client.getSyncStateCalls()
			if syncCalls < 1 {
				return false
			}

			// Should have only one api call.
			r.Equal(1, syncCalls)

			// Should not send any scanned images reports.
			sentMetas := client.getSentMetas()
			r.Len(sentMetas, 0)
			return true
		})
	})
}

type mockImageScanner struct {
	mu   sync.Mutex
	imgs []ScanImageParams
}

func (m *mockImageScanner) ScanImage(ctx context.Context, cfg ScanImageParams) (err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.imgs = append(m.imgs, cfg)
	return nil
}

func (m *mockImageScanner) getScanImageParams() []ScanImageParams {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.imgs
}

type mockCastaiClient struct {
	mu    sync.Mutex
	metas []*castai.ImageMetadata

	imagesResourcesChanges []*castai.ImagesResourcesChange

	syncState      *castai.SyncStateResponse
	syncStateCalls int
}

func (m *mockCastaiClient) SendImagesResourcesChange(ctx context.Context, report *castai.ImagesResourcesChange) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.imagesResourcesChanges = append(m.imagesResourcesChanges, report)
	return nil
}

func (m *mockCastaiClient) GetSyncState(ctx context.Context, filter *castai.SyncStateFilter) (*castai.SyncStateResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.syncStateCalls++
	if m.syncState != nil {
		return m.syncState, nil
	}
	return &castai.SyncStateResponse{}, nil
}

func (m *mockCastaiClient) SendImageMetadata(ctx context.Context, meta *castai.ImageMetadata) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.metas = append(m.metas, meta)
	return nil
}

func (m *mockCastaiClient) getSentMetas() []*castai.ImageMetadata {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.metas
}

func (m *mockCastaiClient) getImagesResourcesChanges() []*castai.ImagesResourcesChange {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.imagesResourcesChanges
}

func (m *mockCastaiClient) getSyncStateCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.syncStateCalls
}
