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

		delta := NewDeltaState(nil)

		pod1 := createPod("nginx1", "img1", "node1")
		pod2 := createPod("nginx2", "img2", "node1")
		pod3 := createPod("nginx1", "img1", "node2")

		// Insert new pods.
		delta.upsert(pod1)
		delta.upsert(pod2)
		delta.upsert(pod3)
		r.Len(delta.images, 2)
		img1 := delta.images["img1"]
		r.Len(img1.nodes, 2)
		r.Equal("nginx1", img1.name)
		r.Equal("img1", img1.id)
		r.Len(img1.owners, 2)
		r.Len(img1.nodes["node1"].podIDs, 1)
		r.Len(delta.images["img2"].nodes, 1)

		// Delete single pod. It should be removed only from image nodes list.
		delta.delete(pod1)
		r.Len(delta.images, 2)
		r.Len(img1.nodes, 2)
		r.Len(img1.nodes["node1"].podIDs, 0)

		// Delete one more pod for the same image. Image should be removed.
		delta.delete(pod3)
		r.Len(delta.images, 2)
		r.Len(delta.images["img2"].nodes, 1)
	})

	t.Run("find best node for image scan", func(t *testing.T) {
		r := require.New(t)

		delta := NewDeltaState(nil)

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
		delta := NewDeltaState(nil)

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

	t.Run("checks free resources", func(t *testing.T) {
		r := require.New(t)
		delta := NewDeltaState(nil)
		twoGigs := resource.MustParse("2Gi")
		twoCpu := resource.MustParse("2")
		delta.nodes["test_node"] = &node{
			name:           "test_node",
			allocatableMem: twoGigs.AsDec(),
			allocatableCPU: twoCpu.AsDec(),
			pods:           map[types.UID]*pod{},
		}
		oneGig := resource.MustParse("1Gi")
		oneCpu := resource.MustParse("1")
		r.True(delta.nodeHasEnoughResources("test_node", oneGig.AsDec(), oneCpu.AsDec()))
		threeGig := resource.MustParse("3Gi")
		threeCpu := resource.MustParse("3")
		r.False(delta.nodeHasEnoughResources("test_node", threeGig.AsDec(), threeCpu.AsDec()))
		r.False(delta.nodeHasEnoughResources("test_node", oneGig.AsDec(), threeCpu.AsDec()))
		r.False(delta.nodeHasEnoughResources("test_node", threeGig.AsDec(), oneCpu.AsDec()))
	})
}
