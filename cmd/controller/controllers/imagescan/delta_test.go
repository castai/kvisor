package imagescan

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestDelta(t *testing.T) {
	t.Run("upsert images state on delta changes", func(t *testing.T) {
		r := require.New(t)

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
						Architecture:    defaultImageArch,
						OperatingSystem: defaultImageOs,
					},
					Allocatable: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("2"),
						corev1.ResourceMemory: resource.MustParse("4Gi"),
					},
				},
			}
		}

		createPod := func(imageName, imageID, nodeName string) *corev1.Pod {
			return &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					UID: types.UID(uuid.New().String()),
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "cont",
							Image: imageName,
						},
					},
					NodeName: nodeName,
				},
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
					ContainerStatuses: []corev1.ContainerStatus{
						{
							Name:    "cont",
							Image:   imageName,
							ImageID: imageID,
						},
					},
				},
			}
		}

		delta := newTestDelta()

		pod1 := createPod("nginx1", "img1", "node1")
		pod2 := createPod("nginx2", "img2", "node1")
		pod3 := createPod("nginx1", "img1", "node2")

		// Insert nodes.
		delta.Upsert(createNode("node1"))
		delta.Upsert(createNode("node2"))
		// Insert new pods.
		delta.Upsert(pod1)
		delta.Upsert(pod2)
		delta.Upsert(pod3)
		r.Len(delta.images, 2)
		img1 := delta.images["img1amd64nginx1"]
		r.Equal("nginx1", img1.name)
		r.Equal("img1", img1.id)
		r.Len(img1.owners, 2)

		// Delete single pod. It should be removed only from image nodes list.
		delta.Delete(pod1)
		r.Len(delta.images, 2)

		// Delete one more pod for the same image. Image should be removed.
		delta.Delete(pod3)
		r.Len(delta.images, 1)
	})

	t.Run("cleans up image references", func(t *testing.T) {
		r := require.New(t)
		delta := newTestDelta()

		node := &corev1.Node{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Node",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "node1",
			},
			Status: corev1.NodeStatus{
				Allocatable: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("2"),
					corev1.ResourceMemory: resource.MustParse("4Gi"),
				},
			},
		}
		delta.Upsert(node)

		pod := &corev1.Pod{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Pod",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				UID: "123",
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "test",
						Image: "test",
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("1"),
								corev1.ResourceMemory: resource.MustParse("2Gi"),
							},
						},
					},
				},
				NodeName: "node1",
			},
			Status: corev1.PodStatus{
				Phase: corev1.PodRunning,
				ContainerStatuses: []corev1.ContainerStatus{
					{
						Name:    "test",
						ImageID: "testid",
					},
				},
			},
		}

		delta.Upsert(pod)
		img, found := delta.images["testidamd64test"]
		r.True(found)
		r.Len(img.owners, 1)

		delta.Delete(pod)
		img, found = delta.images["testidamd64test"]
		r.False(found)
	})

	t.Run("skip ignored namespaces", func(t *testing.T) {
		r := require.New(t)
		delta := newTestDelta()
		delta.ignoredNamespaces = map[string]struct{}{
			"kube-system": {},
		}
		pod := &corev1.Pod{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Pod",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				UID:       "123",
				Namespace: "kube-system",
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "test",
						Image: "test",
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("1"),
								corev1.ResourceMemory: resource.MustParse("2Gi"),
							},
						},
					},
				},
				NodeName: "node1",
			},
			Status: corev1.PodStatus{
				Phase: corev1.PodRunning,
				ContainerStatuses: []corev1.ContainerStatus{
					{
						Name:    "test",
						ImageID: "testid",
					},
				},
			},
		}
		delta.Upsert(pod)

		r.Len(delta.images, 0)
	})
}

func newTestDelta() *deltaState {
	return newDeltaState(&mockKubeController{}, make(map[string]struct{}))
}
