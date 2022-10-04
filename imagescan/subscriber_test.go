package imagescan

import (
	"context"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	mock_castai "github.com/castai/sec-agent/castai/mock"
)

func TestSubscriber(t *testing.T) {

	ctx := context.Background()
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	t.Run("schedule and finish scan", func(t *testing.T) {
		r := require.New(t)
		ctrl := gomock.NewController(t)
		client := mock_castai.NewMockClient(ctrl)

		nginxPod1 := &corev1.Pod{
			TypeMeta: metav1.TypeMeta{Kind: "Pod", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				UID:       types.UID(uuid.New().String()),
				Name:      "nginx-1",
				Namespace: "default",
			},
			Spec: corev1.PodSpec{
				NodeName: "n1",
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
				NodeName: "n2",
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
					NodeName: "n2",
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
					Phase: corev1.PodSucceeded,
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

		cfg := Config{ScanInterval: 1 * time.Millisecond}

		scanner := &mockImageScanner{}
		sub := NewSubscriber(log, cfg, client, scanner, 21)
		ctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		defer cancel()

		sub.OnAdd(nginxPod1)
		sub.OnAdd(nginxPod2)
		sub.OnAdd(argoPod1)
		sub.OnAdd(argoPod2)
		sub.OnAdd(argoReplicaSet)
		sub.OnAdd(argoDeployment)
		err := sub.Run(ctx)
		r.True(errors.Is(err, context.DeadlineExceeded))

		sort.Slice(scanner.imgs, func(i, j int) bool {
			return scanner.imgs[i].ImageName < scanner.imgs[j].ImageName
		})
		r.Len(scanner.imgs, 3)
		argoImg := scanner.imgs[0]
		argoInitImg := scanner.imgs[1]
		ngnxImage := scanner.imgs[2]
		r.Equal("argocd:0.0.1", argoImg.ImageName)
		r.Equal("init-argo:0.0.1", argoInitImg.ImageName)
		r.Equal([]string{string(argoDeployment.UID)}, argoImg.ResourceIDs)

		actualNginxPodResourceIDs := []string{string(nginxPod1.UID), string(nginxPod2.UID)}
		sort.Strings(ngnxImage.ResourceIDs)
		sort.Strings(actualNginxPodResourceIDs)
		r.Equal(ngnxImage.ResourceIDs, actualNginxPodResourceIDs)
		r.NotEmpty(ngnxImage.NodeName)
		r.Equal(ScanImageParams{
			ImageName:         "nginx:1.23",
			ImageID:           "nginx:1.23@sha256",
			ContainerID:       "containerd://sha256",
			NodeName:          ngnxImage.NodeName,
			ResourceIDs:       ngnxImage.ResourceIDs,
			DeleteFinishedJob: true,
			WaitForCompletion: true,
		}, ngnxImage)
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
