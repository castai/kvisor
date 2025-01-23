package kube

import (
	"context"
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
			r.Equal(ip4.Service.GetName(), "s1")
		})

		t.Run("ipv6 added to index", func(t *testing.T) {
			ip6 := client.index.ipsDetails[netip.MustParseAddr("fd01::1")]
			r.Equal(ip6.Service.GetName(), "s1")
		})
	})

	t.Run("add pod", func(t *testing.T) {
		r := require.New(t)
		_, err := clientset.CoreV1().Pods("default").Create(ctx, newTestPod(), metav1.CreateOptions{})
		r.NoError(err)

		r.Eventually(func() bool {
			return countObjects[*corev1.Pod](listener.getItems()) == 1
		}, 2*time.Second, 10*time.Millisecond)

		t.Run("ipv4 added to index", func(t *testing.T) {
			ip4 := client.index.ipsDetails[netip.MustParseAddr("10.10.10.10")]
			r.Equal(ip4.PodInfo.Pod.GetName(), "p1")
		})

		t.Run("ipv6 added to index", func(t *testing.T) {
			ip6 := client.index.ipsDetails[netip.MustParseAddr("fd00::1")]
			r.Equal(ip6.PodInfo.Pod.GetName(), "p1")
		})
	})

	t.Run("delete deployment", func(t *testing.T) {
		r := require.New(t)
		err := clientset.AppsV1().Deployments("default").Delete(ctx, "nginx-1", metav1.DeleteOptions{})
		r.NoError(err)

		r.Eventually(func() bool {
			items := listener.getItems()
			if countObjects[*appsv1.Deployment](items) == 0 {
				if countObjects[*corev1.Pod](listener.getItems()) == 0 {
					t.Fatal("expected to keep pod after deployment delete")
				}
				return true
			}
			return false
		}, 2*time.Second, 10*time.Millisecond)
	})

	t.Run("delete service", func(t *testing.T) {
		r := require.New(t)
		err := clientset.CoreV1().Services("default").Delete(ctx, "s1", metav1.DeleteOptions{})
		r.NoError(err)

		r.Eventually(func() bool {
			return countObjects[*corev1.Service](listener.getItems()) == 0
		}, 2*time.Second, 10*time.Millisecond)

		t.Run("ipv4 removed from index", func(t *testing.T) {
			_, found := client.index.ipsDetails[netip.MustParseAddr("10.30.0.36")]
			r.False(found)
		})

		t.Run("ipv6 removed from index", func(t *testing.T) {
			_, found := client.index.ipsDetails[netip.MustParseAddr("fd01::1")]
			r.False(found)
		})
	})

	t.Run("delete pod", func(t *testing.T) {
		r := require.New(t)
		err := clientset.CoreV1().Pods("default").Delete(ctx, "p1", metav1.DeleteOptions{})
		r.NoError(err)

		r.Eventually(func() bool {
			return countObjects[*corev1.Pod](listener.getItems()) == 0
		}, 2*time.Second, 10*time.Millisecond)

		t.Run("ipv4 removed from index", func(t *testing.T) {
			_, found := client.index.ipsDetails[netip.MustParseAddr("10.30.0.36")]
			r.False(found)
		})

		t.Run("ipv6 removed from index", func(t *testing.T) {
			_, found := client.index.ipsDetails[netip.MustParseAddr("fd00::1")]
			r.False(found)
		})
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
