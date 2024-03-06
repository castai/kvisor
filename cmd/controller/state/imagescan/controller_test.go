package imagescan

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"sync"
	"testing"
	"time"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/controller/kube"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	imgcollectorconfig "github.com/castai/kvisor/cmd/agent/imagescan/config"
)

func TestSubscriber(t *testing.T) {
	ctx := context.Background()
	log := logging.New(&logging.Config{
		Level: slog.LevelDebug,
	})

	createNode := func(name string) *corev1.Node {
		return &corev1.Node{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Node",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
				Labels: map[string]string{
					"provisioner.cast.ai/managed-by": "cast.ai",
				},
			},
			Status: corev1.NodeStatus{
				NodeInfo: corev1.NodeSystemInfo{
					Architecture:    "amd64",
					OperatingSystem: "linux",
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

		createArgoPod := func(podName string) *corev1.Pod {
			return &corev1.Pod{
				TypeMeta: metav1.TypeMeta{Kind: "Pod", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					UID:       types.UID(uuid.New().String()),
					Name:      podName,
					Namespace: "argo",
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

		cfg := Config{
			ScanInterval:       1 * time.Millisecond,
			ScanTimeout:        time.Minute,
			Mode:               "hostfs",
			MaxConcurrentScans: 5,
			CPURequest:         "500m",
			CPULimit:           "2",
			MemoryRequest:      "100Mi",
			MemoryLimit:        "2Gi",
		}

		client := &mockCastaiClient{}
		scanner := &mockImageScanner{}
		scanner.On("ScanImage", mock.Anything, mock.Anything).Return(nil)
		sub := newTestController(log, cfg)
		sub.client = client
		sub.imageScanner = scanner
		sub.initialScansDelay = 1 * time.Millisecond
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		// Simulate concurrent deltas update.
		go func() {
			for {
				sub.OnUpdate(node1)
				sub.OnUpdate(node2)
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
			r.Equal("argocd:0.0.1", argoImg.ImageName)
			r.Equal("init-argo:0.0.1", argoInitImg.ImageName)
			expectedArgoPodResourceIDs := []string{string(argoPod1.UID), string(argoPod2.UID)}
			sort.Strings(argoImg.ResourceIDs)
			sort.Strings(expectedArgoPodResourceIDs)
			r.Equal(expectedArgoPodResourceIDs, argoImg.ResourceIDs)

			ngnxImage := imgs[2]
			expectedNginxPodResourceIDs := []string{string(nginxPod1.UID), string(nginxPod2.UID)}
			sort.Strings(ngnxImage.ResourceIDs)
			sort.Strings(expectedNginxPodResourceIDs)
			r.Equal(expectedNginxPodResourceIDs, ngnxImage.ResourceIDs)
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
				Architecture:                defaultImageArch,
				Os:                          defaultImageOs,
				ScanImageDetails: kube.ImageDetails{
					ImageName:        "kvisor",
					ImagePullSecrets: nil,
				},
			}, ngnxImage)
			r.Len(client.getImagesResourcesChanges(), 1)
			r.Len(client.getImagesResourcesChanges()[0].Images, 3)
			r.Equal(castaipb.ImageScanStatus_IMAGE_SCAN_STATUS_PENDING, client.getImagesResourcesChanges()[0].Images[0].ScanStatus)
			r.Equal(castaipb.ImageScanStatus_IMAGE_SCAN_STATUS_PENDING, client.getImagesResourcesChanges()[0].Images[1].ScanStatus)
			r.Equal(castaipb.ImageScanStatus_IMAGE_SCAN_STATUS_PENDING, client.getImagesResourcesChanges()[0].Images[2].ScanStatus)

			return true
		})

	})

	t.Run("retry failed images", func(t *testing.T) {
		r := require.New(t)

		cfg := Config{
			ScanInterval:       1 * time.Millisecond,
			ScanTimeout:        time.Minute,
			MaxConcurrentScans: 5,
			CPURequest:         "500m",
			CPULimit:           "2",
			MemoryRequest:      "100Mi",
			MemoryLimit:        "2Gi",
		}

		client := &mockCastaiClient{}
		scanner := &mockImageScanner{}
		sub := newTestController(log, cfg)
		sub.client = client
		sub.imageScanner = scanner
		sub.initialScansDelay = 1 * time.Millisecond
		sub.timeGetter = func() time.Time {
			return time.Now().UTC().Add(time.Hour)
		}
		delta := sub.delta
		img := newImage()
		img.name = "img"
		img.id = "img1"
		img.key = "img1amd64img"
		img.architecture = "amd64"
		img.nodes = map[string]*imageNode{
			"node1": {},
		}
		img.owners = map[string]*imageOwner{
			"r1": {},
		}

		delta.images[img.key] = img

		resMem := resource.MustParse("500Mi")
		resCpu := resource.MustParse("2")
		delta.nodes["node1"] = &node{
			name:           "node1",
			allocatableMem: resMem.AsDec(),
			allocatableCPU: resCpu.AsDec(),
			pods:           map[types.UID]*pod{},
			architecture:   defaultImageArch,
			os:             defaultImageOs,
		}

		expectedErr := errors.New("failed")
		scanner.On("ScanImage", mock.Anything, mock.Anything).Return(expectedErr).Once()
		scanner.On("ScanImage", mock.Anything, mock.Anything).Return(nil).Once()

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

			r.Len(imgs, 2)
			img = delta.images[img.key]
			r.False(img.nextScan.IsZero())

			r.Len(client.getImagesResourcesChanges(), 2)
			// first scan update is pending
			r.Len(client.getImagesResourcesChanges()[0].Images, 1)
			r.Equal(castaipb.ImageScanStatus_IMAGE_SCAN_STATUS_PENDING, client.getImagesResourcesChanges()[0].Images[0].ScanStatus)
			r.Empty(client.getImagesResourcesChanges()[0].Images[0].ScanError)
			// second scan update is error
			r.Len(client.getImagesResourcesChanges()[1].Images, 1)
			r.Equal(castaipb.ImageScanStatus_IMAGE_SCAN_STATUS_SCAN_ERROR, client.getImagesResourcesChanges()[1].Images[0].ScanStatus)
			r.Equal(expectedErr.Error(), client.getImagesResourcesChanges()[1].Images[0].ScanError)
			return true
		})
	})

	t.Run("scan image with remote mode fallback", func(t *testing.T) {
		r := require.New(t)

		cfg := Config{
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
		scanner.On("ScanImage", mock.Anything, mock.Anything).Return(nil)
		sub := newTestController(log, cfg)
		sub.imageScanner = scanner
		sub.initialScansDelay = 1 * time.Millisecond
		sub.timeGetter = func() time.Time {
			return time.Now().UTC().Add(time.Hour)
		}
		delta := sub.delta
		img := newImage()
		img.name = "img"
		img.id = "img1"
		img.key = "img1amd64img"
		img.architecture = "amd64"
		img.containerRuntime = imgcollectorconfig.RuntimeContainerd
		img.nodes = map[string]*imageNode{
			"node1": {},
		}
		img.owners = map[string]*imageOwner{
			"r1": {},
		}
		delta.images[img.key] = img
		delta.setImageScanError(img, errImageScanLayerNotFound)

		resMem := resource.MustParse("500Mi")
		resCpu := resource.MustParse("2")
		delta.nodes["node1"] = &node{
			name:           "node1",
			allocatableMem: resMem.AsDec(),
			allocatableCPU: resCpu.AsDec(),
			pods:           map[types.UID]*pod{},
			os:             defaultImageOs,
			architecture:   defaultImageArch,
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

		cfg := Config{
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
		scanner.On("ScanImage", mock.Anything, mock.Anything).Return(nil)
		client := &mockCastaiClient{}
		podOwnerGetter := &mockKubeController{}
		sub := NewController(log, cfg, scanner, client, podOwnerGetter)
		sub.initialScansDelay = 1 * time.Millisecond
		sub.timeGetter = func() time.Time {
			return time.Now().UTC().Add(time.Hour)
		}
		delta := sub.delta
		img := newImage()
		img.name = "img"
		img.id = "img1"
		img.key = "img1amd64img"
		img.architecture = "amd64"
		img.containerRuntime = imgcollectorconfig.RuntimeContainerd
		img.owners = map[string]*imageOwner{
			"r1": {},
		}
		delta.images[img.key] = img

		resMem := resource.MustParse("500Mi")
		resCpu := resource.MustParse("2")
		delta.nodes["node1"] = &node{
			name:           "node1",
			allocatableMem: resMem.AsDec(),
			allocatableCPU: resCpu.AsDec(),
			pods:           map[types.UID]*pod{},
			os:             defaultImageOs,
			architecture:   defaultImageArch,
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

		cfg := Config{
			ScanInterval:       1 * time.Millisecond,
			ScanTimeout:        time.Minute,
			MaxConcurrentScans: 5,
			CPURequest:         "500m",
			CPULimit:           "2",
			MemoryRequest:      "100Mi",
			MemoryLimit:        "2Gi",
			Mode:               string(imgcollectorconfig.ModeHostFS),
		}

		scanner := &mockImageScanner{}
		scanner.On("ScanImage", mock.Anything, mock.Anything).Return(nil)
		sub := newTestController(log, cfg)
		sub.imageScanner = scanner
		sub.initialScansDelay = 1 * time.Millisecond
		delta := sub.delta
		img := newImage()
		img.name = "img"
		img.id = "img1"
		img.key = "img1amd64img"
		img.architecture = "amd64"
		img.nodes = map[string]*imageNode{
			"node1": {},
		}
		img.owners = map[string]*imageOwner{
			"r1": {},
		}
		delta.images[img.key] = img

		firstCtx, firstCancel := context.WithTimeout(ctx, 50*time.Millisecond)
		defer firstCancel()

		err := sub.scheduleScans(firstCtx)
		r.NoError(err)
		// without nodes in delta it should not schedule scan.
		r.Empty(scanner.imgs)

		resMem := resource.MustParse("500Mi")
		resCpu := resource.MustParse("2")
		// with two nodes it should scan without resource check.
		delta.nodes["test_a"] = &node{
			architecture: defaultImageArch,
			os:           defaultImageOs,
		}
		delta.nodes["node1"] = &node{
			name:           "node1",
			allocatableMem: resMem.AsDec(),
			allocatableCPU: resCpu.AsDec(),
			pods:           map[types.UID]*pod{},
			castaiManaged:  true,
			architecture:   defaultImageArch,
			os:             defaultImageOs,
		}
		img = newImage()
		img.name = "img"
		img.id = "img1"
		img.key = "img1amd64img"
		img.architecture = "amd64"
		img.nodes = map[string]*imageNode{
			"node1": {},
		}
		img.owners = map[string]*imageOwner{
			"r1": {},
		}
		delta.images[img.key] = img

		secondCtx, secondCancel := context.WithTimeout(ctx, 50*time.Millisecond)
		defer secondCancel()

		err = sub.scheduleScans(secondCtx)
		r.NoError(err)
		r.Len(scanner.imgs, 1)
		r.True(delta.images[img.key].scanned)
	})

	t.Run("send changed resource owners", func(t *testing.T) {
		r := require.New(t)

		cfg := Config{
			ScanInterval: 1 * time.Millisecond,
		}

		client := &mockCastaiClient{}
		sub := newTestController(log, cfg)
		sub.client = client
		sub.initialScansDelay = 1 * time.Millisecond
		sub.timeGetter = func() time.Time {
			return time.Now().UTC().Add(time.Hour)
		}
		delta := sub.delta
		img := newImage()
		img.name = "img"
		img.id = "img1"
		img.key = "img1amd64img"
		img.architecture = "amd64"
		img.owners = map[string]*imageOwner{
			"r1": {},
		}
		delta.images[img.key] = img

		ctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		defer cancel()

		errc := make(chan error, 1)
		go func() {
			errc <- sub.Run(ctx)
		}()

		assertLoop(errc, func() bool {
			changes := client.getImagesResourcesChanges()

			// Should have only 1 call to api because there are no delta updates
			r.Len(changes, 1)

			// First api call. Initial full resync.
			change1Img1 := changes[0].Images[0]
			r.Equal("img1", change1Img1.Id)
			r.Equal("amd64", change1Img1.Architecture)
			r.Equal([]string{"r1"}, change1Img1.ResourceIds)

			return true
		})
	})

	t.Run("sync scanned images from remote state", func(t *testing.T) {
		r := require.New(t)

		cfg := Config{
			ScanInterval:       1 * time.Millisecond,
			ScanTimeout:        time.Minute,
			MaxConcurrentScans: 5,
			CPURequest:         "500m",
			CPULimit:           "2",
			MemoryRequest:      "100Mi",
			MemoryLimit:        "2Gi",
		}

		scanner := &mockImageScanner{}
		scanner.On("ScanImage", mock.Anything, mock.Anything).Return(nil)
		client := &mockCastaiClient{
			syncState: &castaipb.GetSyncStateResponse{
				Images: &castaipb.ImagesSyncState{
					Images: []*castaipb.Image{
						{
							Id:           "img1",
							Architecture: "amd64",
						},
						{
							Id:           "img2",
							Architecture: "amd64",
						},
					},
				},
			},
		}
		sub := newTestController(log, cfg)
		sub.imageScanner = scanner
		sub.client = client
		sub.initialScansDelay = 1 * time.Millisecond
		sub.timeGetter = func() time.Time {
			return time.Now().UTC().Add(time.Hour)
		}
		delta := sub.delta
		img1 := newImage()
		img1.name = "img1"
		img1.id = "img1"
		img1.key = "img1amd64img1"
		img1.architecture = "amd64"
		img1.owners = map[string]*imageOwner{
			"r1": {},
		}
		delta.images[img1.key] = img1

		img2 := newImage()
		img2.name = "img2"
		img2.id = "img2"
		img2.key = "img2amd64img2"
		img2.architecture = "amd64"
		img2.owners = map[string]*imageOwner{
			"r2": {},
		}
		delta.images[img2.key] = img2

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
			return true
		})
	})
}

func TestController_findBestNodeAndMode(t *testing.T) {
	log := logging.New(&logging.Config{Level: slog.LevelDebug})

	t.Run("fallbacks when img had error", func(t *testing.T) {
		cfg := Config{
			Mode:          string(imgcollectorconfig.ModeHostFS),
			CPURequest:    "1",
			MemoryRequest: "100Mi",
		}

		resMem := resource.MustParse("500Mi")
		resCpu := resource.MustParse("2")

		lessResMem := resource.MustParse("400Mi")
		lessResCpu := resource.MustParse("1")

		controller := newTestController(log, cfg)
		controller.delta.nodes = map[string]*node{
			"node1": {
				name:           "node1",
				architecture:   defaultImageArch,
				os:             defaultImageOs,
				allocatableMem: resMem.AsDec(),
				allocatableCPU: resCpu.AsDec(),
				castaiManaged:  true,
			},
			"node2": {
				name:           "node2",
				architecture:   defaultImageArch,
				os:             defaultImageOs,
				allocatableMem: lessResMem.AsDec(),
				allocatableCPU: lessResCpu.AsDec(),
				castaiManaged:  true,
			},
		}

		img := &image{
			key: "img1amd64img",
			nodes: map[string]*imageNode{
				"node1": {},
				"node2": {},
			},
			lastScanErr: errImageScanLayerNotFound,
		}

		r := require.New(t)
		node, mode, err := controller.findBestNodeAndMode(img)
		r.NoError(err)
		r.Equal(string(imgcollectorconfig.ModeRemote), mode)
		r.Equal("node1", node)
	})

	t.Run("fallbacks when no cast ai managed nodes", func(t *testing.T) {
		cfg := Config{
			Mode:          string(imgcollectorconfig.ModeHostFS),
			CPURequest:    "1",
			MemoryRequest: "100Mi",
		}

		resMem := resource.MustParse("500Mi")
		resCpu := resource.MustParse("2")

		lessResMem := resource.MustParse("400Mi")
		lessResCpu := resource.MustParse("1")

		controller := newTestController(log, cfg)
		controller.delta.nodes = map[string]*node{
			"node1": {
				name:           "node1",
				architecture:   defaultImageArch,
				os:             defaultImageOs,
				allocatableMem: resMem.AsDec(),
				allocatableCPU: resCpu.AsDec(),
				castaiManaged:  false,
			},
			"node2": {
				name:           "node2",
				architecture:   defaultImageArch,
				os:             defaultImageOs,
				allocatableMem: lessResMem.AsDec(),
				allocatableCPU: lessResCpu.AsDec(),
				castaiManaged:  false,
			},
		}

		img := &image{
			key: "img1amd64img",
			nodes: map[string]*imageNode{
				"node1": {},
				"node2": {},
			},
		}

		r := require.New(t)
		node, mode, err := controller.findBestNodeAndMode(img)
		r.NoError(err)
		r.Equal(string(imgcollectorconfig.ModeRemote), mode)
		r.Equal("node1", node)
	})

	t.Run("fallbacks when no resources on cast ai managed nodes", func(t *testing.T) {
		cfg := Config{
			Mode:          string(imgcollectorconfig.ModeHostFS),
			CPURequest:    "2",
			MemoryRequest: "400Mi",
		}

		resMem := resource.MustParse("500Mi")
		resCpu := resource.MustParse("2")

		lessResMem := resource.MustParse("400Mi")
		lessResCpu := resource.MustParse("1")

		controller := newTestController(log, cfg)
		controller.delta.nodes = map[string]*node{
			"node1": {
				name:           "node1",
				architecture:   defaultImageArch,
				os:             defaultImageOs,
				allocatableMem: resMem.AsDec(),
				allocatableCPU: resCpu.AsDec(),
				castaiManaged:  false,
			},
			"node2": {
				name:           "node2",
				architecture:   defaultImageArch,
				os:             defaultImageOs,
				allocatableMem: lessResMem.AsDec(),
				allocatableCPU: lessResCpu.AsDec(),
				castaiManaged:  true,
			},
		}

		img := &image{
			key: "img1amd64img",
			nodes: map[string]*imageNode{
				"node2": {},
			},
		}

		r := require.New(t)
		node, mode, err := controller.findBestNodeAndMode(img)
		r.NoError(err)
		r.Equal(string(imgcollectorconfig.ModeRemote), mode)
		r.Equal("node1", node)
	})

	t.Run("picks correct node", func(t *testing.T) {
		cfg := Config{
			Mode:          string(imgcollectorconfig.ModeHostFS),
			CPURequest:    "2",
			MemoryRequest: "400Mi",
		}

		resMem := resource.MustParse("500Mi")
		resCpu := resource.MustParse("2")

		lessResMem := resource.MustParse("400Mi")
		lessResCpu := resource.MustParse("1")

		controller := newTestController(log, cfg)
		controller.delta.nodes = map[string]*node{
			"node1": {
				name:           "node1",
				architecture:   defaultImageArch,
				os:             defaultImageOs,
				allocatableMem: resMem.AsDec(),
				allocatableCPU: resCpu.AsDec(),
				castaiManaged:  true,
			},
			"node2": {
				name:           "node2",
				architecture:   "amd64",
				os:             "linux",
				allocatableMem: lessResMem.AsDec(),
				allocatableCPU: lessResCpu.AsDec(),
				castaiManaged:  true,
			},
		}

		img := &image{
			key: "img1amd64img",
			nodes: map[string]*imageNode{
				"node1": {},
				"node2": {},
			},
		}

		r := require.New(t)
		node, mode, err := controller.findBestNodeAndMode(img)
		r.NoError(err)
		r.Equal(string(imgcollectorconfig.ModeHostFS), mode)
		r.Equal("node1", node)
	})
}

func newTestController(log *logging.Logger, cfg Config) *Controller {
	scanner := &mockImageScanner{}
	client := &mockCastaiClient{}
	podOwnerGetter := &mockKubeController{}
	return NewController(log, cfg, scanner, client, podOwnerGetter)
}

type mockImageScanner struct {
	mu   sync.Mutex
	imgs []ScanImageParams
	mock.Mock
}

func (m *mockImageScanner) ScanImage(ctx context.Context, cfg ScanImageParams) (err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.imgs = append(m.imgs, cfg)
	return m.Called(ctx, cfg).Error(0)
}

func (m *mockImageScanner) getScanImageParams() []ScanImageParams {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.imgs
}

type mockKubeController struct {
}

func (m *mockKubeController) GetOwnerUID(obj kube.Object) string {
	return string(obj.GetUID())
}

func (m *mockKubeController) GetKvisorAgentImageDetails() (kube.ImageDetails, bool) {
	return kube.ImageDetails{
		ImageName:        "kvisor",
		ImagePullSecrets: nil,
	}, true
}

type mockCastaiClient struct {
	mu    sync.Mutex
	metas []*castaipb.ImageMetadata

	imagesResourcesChanges []*castaipb.UpdateSyncStateRequest

	syncState      *castaipb.GetSyncStateResponse
	syncStateCalls int
}

func (m *mockCastaiClient) GetSyncState(ctx context.Context, in *castaipb.GetSyncStateRequest, opts ...grpc.CallOption) (*castaipb.GetSyncStateResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.syncStateCalls++
	if m.syncState != nil {
		return m.syncState, nil
	}
	return &castaipb.GetSyncStateResponse{}, nil
}

func (m *mockCastaiClient) UpdateSyncState(ctx context.Context, in *castaipb.UpdateSyncStateRequest, opts ...grpc.CallOption) (*castaipb.UpdateSyncStateResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.imagesResourcesChanges = append(m.imagesResourcesChanges, in)
	return &castaipb.UpdateSyncStateResponse{}, nil
}

func (m *mockCastaiClient) getImagesResourcesChanges() []*castaipb.UpdateSyncStateRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.imagesResourcesChanges
}

func (m *mockCastaiClient) getSyncStateCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.syncStateCalls
}
