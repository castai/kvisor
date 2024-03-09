package kube

import (
	"context"
	"fmt"
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

	t.Run("call event handlers and listeners", func(t *testing.T) {
		r := require.New(t)
		dep1 := newTestDeployment()
		pod1 := newTestPod()
		clientset := fake.NewSimpleClientset(dep1, pod1)
		lis := &mockListener{items: map[types.UID]Object{}}
		informersFactory := informers.NewSharedInformerFactory(clientset, 0)
		client := NewClient(log, "castai-kvisor", "kvisor", Version{}, clientset)
		client.RegisterHandlers(informersFactory)
		client.RegisterPodsHandlers(informersFactory)
		client.RegisterKubernetesChangeListener(lis)
		informersFactory.Start(ctx.Done())
		informersFactory.WaitForCacheSync(ctx.Done())

		// Assert added deployment.
		r.Eventually(func() bool {
			items := lis.getItems()
			if len(items) == 2 {
				return true
			}
			return false
		}, 2*time.Second, 10*time.Millisecond)

		r.NoError(clientset.AppsV1().Deployments(dep1.Namespace).Delete(ctx, dep1.Name, metav1.DeleteOptions{}))

		// Assert deployment is deleted.
		r.Eventually(func() bool {
			items := lis.getItems()
			if len(items) == 1 {
				item := items[0]
				if reflect.TypeOf(item) != reflect.TypeOf(&corev1.Pod{}) {
					t.Fatal("expected to keep pod after deployment delete")
				}
				return true
			}
			return false
		}, 2*time.Second, 10*time.Millisecond)
	})
}

func aa(ob Object) {
	fmt.Println(reflect.TypeOf(ob))
}

type mockListener struct {
	items map[types.UID]Object
	mu    sync.Mutex
}

func (m *mockListener) RequiredTypes() []reflect.Type {
	return []reflect.Type{
		reflect.TypeOf(&corev1.Pod{}),
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
			UID:       types.UID("111b56a9-ab5e-4a35-93af-f092e2f63011"),
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

func newTestPod() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "p1",
			Namespace: "default",
			UID:       types.UID("111b56a9-ab5e-4a35-93af-f092e2f63022"),
		},
	}
}
