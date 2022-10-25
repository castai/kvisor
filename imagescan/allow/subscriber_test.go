package allow

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestSubscriber(t *testing.T) {
	t.Run("calculates resources correctly", func(t *testing.T) {
		r := require.New(t)
		subscriber := NewSubscriber()

		subscriber.OnAdd(&corev1.Node{
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
		subscriber.OnAdd(&corev1.Node{
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

		qty := resource.MustParse("1Gi")
		nodeName, err := subscriber.FindBestNode([]string{"node2", "node1"}, qty.AsDec())
		r.NoError(err)
		r.Equal("node1", nodeName)

		qty = resource.MustParse("500Mi")
		nodeName, err = subscriber.FindBestNode([]string{"node2", "node1"}, qty.AsDec())
		r.NoError(err)
		r.Equal("node2", nodeName)

		subscriber.OnAdd(&corev1.Node{
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

		qty = resource.MustParse("500Mi")
		nodeName, err = subscriber.FindBestNode([]string{"node3", "node2", "node1"}, qty.AsDec())
		r.NoError(err)
		r.Equal("node3", nodeName)

		subscriber.OnAdd(&corev1.Pod{
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

		nodeName, err = subscriber.FindBestNode([]string{"node3", "node2", "node1"}, qty.AsDec())
		r.NoError(err)
		r.Equal("node2", nodeName)
	})

	t.Run("returns error when no nodes", func(t *testing.T) {
		r := require.New(t)
		subscriber := NewSubscriber()

		subscriber.OnAdd(&corev1.Node{
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
					corev1.ResourceMemory: resource.MustParse("2Gi"),
				},
			},
		})

		qty := resource.MustParse("1Gi")
		nodeName, err := subscriber.FindBestNode([]string{"node1"}, qty.AsDec())
		r.NoError(err)
		r.Equal("node1", nodeName)

		subscriber.OnAdd(&corev1.Pod{
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

		_, err = subscriber.FindBestNode([]string{"node3", "node2", "node1"}, qty.AsDec())
		r.ErrorIs(err, ErrNoCandidates)

		subscriber.OnAdd(&corev1.Pod{
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
								corev1.ResourceMemory: resource.MustParse("1Gi"),
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

		nodeName, err = subscriber.FindBestNode([]string{"node1"}, qty.AsDec())
		r.NoError(err)
		r.Equal("node1", nodeName)
	})
}
