package imagescan

import (
	"errors"
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
						Architecture: "amd64",
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
		delta.upsert(createNode("node1"))
		delta.upsert(createNode("node2"))
		// Insert new pods.
		delta.upsert(pod1)
		delta.upsert(pod2)
		delta.upsert(pod3)
		r.Len(delta.images, 2)
		img1 := delta.images["img1amd64nginx1"]
		r.Len(img1.nodes, 2)
		r.Equal("nginx1", img1.name)
		r.Equal("img1", img1.id)
		r.Len(img1.owners, 2)
		r.Len(img1.nodes["node1"].podIDs, 1)
		r.Len(delta.images["img2amd64nginx2"].nodes, 1)

		// Delete single pod. It should be removed only from image nodes list.
		delta.delete(pod1)
		r.Len(delta.images, 2)
		r.Len(img1.nodes, 2)
		r.Empty(img1.nodes["node1"].podIDs)

		// Delete one more pod for the same image. Image should be removed.
		delta.delete(pod3)
		r.Len(delta.images, 2)
		r.Len(delta.images["img2amd64nginx2"].nodes, 1)
	})

	t.Run("find best node for image scan", func(t *testing.T) {
		r := require.New(t)

		delta := newTestDelta()

		delta.upsert(&corev1.Node{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Node",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "node1",
			},
			Status: corev1.NodeStatus{
				Allocatable: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("500m"),
					corev1.ResourceMemory: resource.MustParse("2Gi"),
				},
			},
		})
		delta.upsert(&corev1.Node{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Node",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "node2",
			},
			Status: corev1.NodeStatus{
				Allocatable: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("1000m"),
					corev1.ResourceMemory: resource.MustParse("500Mi"),
				},
			},
		})

		cpuQty := resource.MustParse("100m")
		memQty := resource.MustParse("1Gi")
		nodeName, err := delta.findBestNode([]string{"node2", "node1"}, memQty.AsDec(), cpuQty.AsDec())
		r.NoError(err)
		r.Equal("node1", nodeName)

		memQty = resource.MustParse("500Mi")
		nodeName, err = delta.findBestNode([]string{"node2", "node1"}, memQty.AsDec(), cpuQty.AsDec())
		r.NoError(err)
		r.Equal("node2", nodeName)

		delta.upsert(&corev1.Node{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Node",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "node3",
			},
			Status: corev1.NodeStatus{
				Allocatable: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("2"),
					corev1.ResourceMemory: resource.MustParse("500Mi"),
				},
			},
		})

		memQty = resource.MustParse("500Mi")
		nodeName, err = delta.findBestNode([]string{"node3", "node2", "node1"}, memQty.AsDec(), cpuQty.AsDec())
		r.NoError(err)
		r.Equal("node3", nodeName)

		delta.upsert(&corev1.Pod{
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
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("2"),
								corev1.ResourceMemory: resource.MustParse("1Gi"),
							},
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("2"),
								corev1.ResourceMemory: resource.MustParse("1Gi"),
							},
						},
					},
				},
				NodeName: "node3",
			},
			Status: corev1.PodStatus{
				Phase: corev1.PodRunning,
			},
		})

		nodeName, err = delta.findBestNode([]string{"node3", "node2", "node1"}, memQty.AsDec(), cpuQty.AsDec())
		r.NoError(err)
		r.Equal("node2", nodeName)
	})

	t.Run("returns error when no best node find", func(t *testing.T) {
		r := require.New(t)
		delta := newTestDelta()

		delta.upsert(&corev1.Node{
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
		})

		delta.upsert(&corev1.Pod{
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
			},
		})

		cpuQty := resource.MustParse("1")
		memQty := resource.MustParse("4Gi")
		_, err := delta.findBestNode([]string{"node1"}, memQty.AsDec(), cpuQty.AsDec())
		r.ErrorIs(err, errNoCandidates)

		memQty = resource.MustParse("100Mi")
		node, err := delta.findBestNode([]string{"node1"}, memQty.AsDec(), cpuQty.AsDec())
		r.NoError(err)
		r.Equal("node1", node)

		cpuQty = resource.MustParse("2")
		memQty = resource.MustParse("100Mi")
		_, err = delta.findBestNode([]string{"node1"}, memQty.AsDec(), cpuQty.AsDec())
		r.ErrorIs(err, errNoCandidates)
	})

	t.Run("frees up resources", func(t *testing.T) {
		r := require.New(t)
		delta := newTestDelta()

		delta.upsert(&corev1.Node{
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
		})

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
			},
		}

		delta.upsert(pod)
		cpuQty := resource.MustParse("2")
		memQty := resource.MustParse("4Gi")
		_, err := delta.findBestNode([]string{"node1"}, memQty.AsDec(), cpuQty.AsDec())
		r.ErrorIs(err, errNoCandidates)

		delta.delete(pod)
		_, err = delta.findBestNode([]string{"node1"}, memQty.AsDec(), cpuQty.AsDec())
		r.NoError(err)
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
		delta.upsert(node)

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

		delta.upsert(pod)
		img, found := delta.images["testidamd64test"]
		r.True(found)
		r.Len(img.owners, 1)
		r.Len(img.nodes, 1)

		delta.delete(pod)
		img, found = delta.images["testidamd64test"]
		r.True(found)
		r.Empty(img.owners)

		delta.delete(node)
		_, found = delta.nodes["node1"]
		r.False(found)
	})
}

func TestIsPrivateImageErr(t *testing.T) {
	tests := []struct {
		name            string
		err             error
		expectedPrivate bool
	}{
		{name: "unauthorized upper case", err: errors.New("can't get image: UNAUTHORIZED image"), expectedPrivate: true},
		{name: "unauthorized pascal case", err: errors.New("can't get image: Unauthorized image"), expectedPrivate: true},
		{name: "manifest_unknown", err: errors.New("can't get image: MANIFEST_UNKNOWN image"), expectedPrivate: true},
		{name: "denied", err: errors.New("can't get image: DENIED image"), expectedPrivate: true},
		{name: "connection refused", err: errors.New("can't get image: connection refused image"), expectedPrivate: true},
		{name: "context canceled", err: errors.New("can't get image: context canceled"), expectedPrivate: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := require.New(t)
			r.Equal(test.expectedPrivate, isPrivateImageError(test.err))
		})
	}
}

func newTestDelta() *deltaState {
	return newDeltaState(&mockPodOwnerGetter{})
}
