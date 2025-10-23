package kube

import (
	"context"
	"fmt"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/castai/kvisor/pkg/logging"
	"github.com/samber/lo"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
)

func TestClient(t *testing.T) {
	ctx := context.Background()
	log := logging.NewTestLog()

	clientset := fake.NewClientset()
	listener := &mockListener{items: map[types.UID]Object{}}
	informersFactory := informers.NewSharedInformerFactory(clientset, 0)
	client := NewClient(log, "castai-kvisor", "kvisor", Version{}, clientset)
	client.RegisterHandlers(informersFactory)
	client.RegisterPodsHandlers(informersFactory)
	client.RegisterKubernetesChangeListener(listener)
	informersFactory.Start(ctx.Done())
	informersFactory.WaitForCacheSync(ctx.Done())

	t.Run("add deployment", func(t *testing.T) {
		r := require.New(t)
		_, err := clientset.AppsV1().Deployments("default").Create(ctx, newTestDeployment(), metav1.CreateOptions{})
		r.NoError(err)

		r.Eventually(func() bool {
			return countObjects[*appsv1.Deployment](listener.getItems()) == 1
		}, 2*time.Second, 10*time.Millisecond)
	})

	t.Run("add service", func(t *testing.T) {
		r := require.New(t)
		_, err := clientset.CoreV1().Services("default").Create(ctx, newTestService(), metav1.CreateOptions{})
		r.NoError(err)

		r.Eventually(func() bool {
			return countObjects[*corev1.Service](listener.getItems()) == 1
		}, 2*time.Second, 10*time.Millisecond)

		t.Run("ipv4 added to index", func(t *testing.T) {
			ip4 := client.index.ipsDetails[netip.MustParseAddr("10.30.0.36")]
			r.Equal(ip4[0].Service.GetName(), "s1")
		})

		t.Run("ipv6 added to index", func(t *testing.T) {
			ip6 := client.index.ipsDetails[netip.MustParseAddr("fd01::1")]
			r.Equal(ip6[0].Service.GetName(), "s1")
		})
	})

	t.Run("update ip index on pod changes", func(t *testing.T) {
		t.Run("add ip index records on pod creation", func(t *testing.T) {
			r := require.New(t)
			_, err := clientset.CoreV1().Pods("default").Create(ctx, newTestPod(), metav1.CreateOptions{})
			r.NoError(err)

			r.Eventually(func() bool {
				return countObjects[*corev1.Pod](listener.getItems()) == 1
			}, 2*time.Second, 10*time.Millisecond)

			t.Run("ipv4 added to index", func(t *testing.T) {
				ip4 := client.index.ipsDetails[netip.MustParseAddr("10.10.10.10")]
				r.Equal(ip4[0].PodInfo.Pod.GetName(), "p1")
			})

			t.Run("ipv6 added to index", func(t *testing.T) {
				ip6 := client.index.ipsDetails[netip.MustParseAddr("fd00::1")]
				r.Equal(ip6[0].PodInfo.Pod.GetName(), "p1")
			})
		})

		t.Run("mark ip index records as deleted on pod deletion", func(t *testing.T) {
			r := require.New(t)
			err := clientset.CoreV1().Pods("default").Delete(ctx, "p1", metav1.DeleteOptions{})
			r.NoError(err)

			r.Eventually(func() bool {
				return countObjects[*corev1.Pod](listener.getItems()) == 0
			}, 2*time.Second, 10*time.Millisecond)

			t.Run("ipv4 removed from index", func(t *testing.T) {
				items, found := client.index.ipsDetails[netip.MustParseAddr("10.10.10.10")]
				r.True(found)
				r.Equal(len(items), 1)
				r.NotNil(items[0].deleteAt)
			})

			t.Run("ipv6 removed from index", func(t *testing.T) {
				items, found := client.index.ipsDetails[netip.MustParseAddr("fd00::1")]
				r.True(found)
				r.Equal(len(items), 1)
				r.NotNil(items[0].deleteAt)
			})
		})

		t.Run("cleanup ip details", func(t *testing.T) {
			r := require.New(t)

			client.index.ipsDetails.cleanup(time.Nanosecond)

			_, found := client.index.ipsDetails[netip.MustParseAddr("10.10.10.10")]
			r.False(found)
		})
	})

	t.Run("delete deployment", func(t *testing.T) {
		r := require.New(t)
		err := clientset.AppsV1().Deployments("default").Delete(ctx, "nginx-1", metav1.DeleteOptions{})
		r.NoError(err)

		r.Eventually(func() bool {
			items := listener.getItems()
			return countObjects[*appsv1.Deployment](items) == 0
		}, 2*time.Second, 10*time.Millisecond)
	})

	t.Run("delete service", func(t *testing.T) {
		r := require.New(t)
		err := clientset.CoreV1().Services("default").Delete(ctx, "s1", metav1.DeleteOptions{})
		r.NoError(err)

		r.Eventually(func() bool {
			return countObjects[*corev1.Service](listener.getItems()) == 0
		}, 2*time.Second, 10*time.Millisecond)

		t.Run("ipv4 is still kept it the index", func(t *testing.T) {
			_, found := client.index.ipsDetails[netip.MustParseAddr("10.30.0.36")]
			r.True(found)
		})

		t.Run("ipv6 is still kept it the index", func(t *testing.T) {
			_, found := client.index.ipsDetails[netip.MustParseAddr("fd01::1")]
			r.True(found)
		})
	})

	t.Run("owner mapping", func(t *testing.T) {
		tests := []struct {
			name              string
			ownerReferences   []metav1.OwnerReference
			expectedOwnerName string
			expectedOwnerKind string
			extraObjectsFunc  func(index *Index)
		}{
			{
				name: "pod with StatefulSet",
				ownerReferences: []metav1.OwnerReference{
					{
						Kind: "StatefulSet",
						Name: "st",
					},
				},
				expectedOwnerName: "st",
				expectedOwnerKind: "StatefulSet",
			},
			{
				name: "pod with DaemonSet",
				ownerReferences: []metav1.OwnerReference{
					{
						Kind: "DaemonSet",
						Name: "ds1",
					},
				},
				expectedOwnerName: "ds1",
				expectedOwnerKind: "DaemonSet",
			},
			{
				name: "pod with Job",
				ownerReferences: []metav1.OwnerReference{
					{
						Kind: "Job",
						Name: "job1",
						UID:  "job1",
					},
				},
				expectedOwnerName: "job1",
				expectedOwnerKind: "Job",
				extraObjectsFunc: func(index *Index) {
					client.index.jobs["job1"] = metav1.ObjectMeta{
						Name: "job1",
					}
				},
			},
			{
				name: "pod with ReplicaSet",
				ownerReferences: []metav1.OwnerReference{
					{
						Kind: "ReplicaSet",
						Name: "rs1",
						UID:  "rs1",
					},
				},
				expectedOwnerName: "rs1",
				expectedOwnerKind: "ReplicaSet",
				extraObjectsFunc: func(index *Index) {
					client.index.replicaSets["rs1"] = metav1.ObjectMeta{
						Name: "rs1",
					}
				},
			},
			{
				name: "pod with Deployment",
				ownerReferences: []metav1.OwnerReference{
					{
						Kind: "ReplicaSet",
						Name: "rs1",
						UID:  "rs1",
					},
				},
				expectedOwnerName: "dep1",
				expectedOwnerKind: "Deployment",
				extraObjectsFunc: func(index *Index) {
					client.index.replicaSets["rs1"] = metav1.ObjectMeta{
						Name: "rs1",
						OwnerReferences: []metav1.OwnerReference{
							{
								Kind: "Deployment",
								Name: "dep1",
								UID:  "dep1",
							},
						},
					}
				},
			},
		}

		for i, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				r := require.New(t)
				pod := newTestPod()
				pod.Namespace = fmt.Sprintf("pod_owner_ns_%d", i)
				pod.ObjectMeta.OwnerReferences = test.ownerReferences
				_, err := clientset.CoreV1().Pods(pod.Namespace).Create(ctx, pod, metav1.CreateOptions{})
				r.NoError(err)
				if test.extraObjectsFunc != nil {
					client.mu.Lock()
					test.extraObjectsFunc(client.index)
					client.mu.Unlock()
				}

				owner := client.index.getPodOwner(pod)
				r.Equal(test.expectedOwnerName, owner.Name)
				r.Equal(test.expectedOwnerKind, owner.Kind)
			})
		}
	})
}

type mockListener struct {
	items map[types.UID]Object
	mu    sync.Mutex
}

func (m *mockListener) RequiredTypes() []reflect.Type {
	return []reflect.Type{
		reflect.TypeOf(&corev1.Pod{}),
		reflect.TypeOf(&corev1.Service{}),
		reflect.TypeOf(&appsv1.Deployment{}),
	}
}

func (m *mockListener) getItems() []Object {
	m.mu.Lock()
	defer m.mu.Unlock()
	return lo.Values(m.items)
}

func (m *mockListener) OnAdd(obj Object) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items[obj.GetUID()] = obj
}

func (m *mockListener) OnDelete(obj Object) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.items, obj.GetUID())
}

func (m *mockListener) OnUpdate(obj Object) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items[obj.GetUID()] = obj
}

func newTestDeployment() *appsv1.Deployment {
	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx-1",
			Namespace: "default",
			UID:       types.UID("deployment-1"),
			OwnerReferences: []metav1.OwnerReference{
				{
					UID:        types.UID("owner"),
					APIVersion: "v1",
					Kind:       "Node",
					Controller: lo.ToPtr(true),
					Name:       "node1",
				},
			},
			Labels: map[string]string{"subscriber": "test"},
		},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					NodeName: "n1",
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.23",
						},
					},
				},
			},
		},
		Status: appsv1.DeploymentStatus{
			Replicas: 1,
		},
	}
}

func newTestService() *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "s1",
			Namespace: "default",
			UID:       types.UID("service-1"),
		},
		Spec: corev1.ServiceSpec{
			Type:       corev1.ServiceTypeClusterIP,
			ClusterIP:  "10.30.0.36",
			ClusterIPs: []string{"10.30.0.36", "fd01::1"},
		},
	}
}

func newTestPod() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "p1",
			Namespace: "default",
			UID:       types.UID("pod-1"),
		},
		Status: corev1.PodStatus{
			PodIP: "10.10.10.10",
			PodIPs: []corev1.PodIP{
				{
					IP: "10.10.10.10",
				},
				{
					IP: "fd00::1",
				},
			},
		},
	}
}

func countObjects[T Object](objects []Object) int {
	count := 0
	for _, obj := range objects {
		if _, ok := obj.(T); ok {
			count++
		}
	}
	return count
}
