package controller

import (
	"context"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/castai/sec-agent/version"
)

func TestController(t *testing.T) {
	ctx := context.Background()
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	t.Run("handle events", func(t *testing.T) {
		r := require.New(t)
		testNs := &corev1.Namespace{
			TypeMeta: metav1.TypeMeta{},
			ObjectMeta: metav1.ObjectMeta{
				Name: "kube-system",
				ManagedFields: []metav1.ManagedFieldsEntry{
					{
						Manager:   "mng",
						Operation: "op",
					},
				},
			},
		}
		testDs := &appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kube-proxy",
				Namespace: "kube-system",
				ManagedFields: []metav1.ManagedFieldsEntry{
					{
						Manager:   "mng",
						Operation: "op",
					},
				},
			},
		}
		clientset := fake.NewSimpleClientset(testNs, testDs)
		informersFactory := informers.NewSharedInformerFactory(clientset, 0)
		testSubs := []ObjectSubscriber{
			newTestSubscriber(log.WithField("sub", "sub1")),
			newTestSubscriber(log.WithField("sub", "sub2")),
		}
		ctrl := New(log, informersFactory, testSubs, version.Version{MinorInt: 22})

		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		errc := make(chan error)
		go func() {
			if err := ctrl.Run(ctx); err != nil {
				errc <- err
			}
		}()

		for i := 0; i < 2; i++ {
			sub := testSubs[i].(*testSubscriber)
			select {
			case err := <-errc:
				t.Fatal(err)
			case <-time.After(1 * time.Millisecond):
				sub.assertNoManagedFields(r)
			}
		}
	})

	t.Run("skip events for unchanged daemon sets", func(t *testing.T) {
		r := require.New(t)
		testDs := &appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kube-proxy",
				Namespace: "kube-system",
				ManagedFields: []metav1.ManagedFieldsEntry{
					{
						Manager:   "mng",
						Operation: "op",
					},
				},
			},
		}
		clientset := fake.NewSimpleClientset(testDs)
		informersFactory := informers.NewSharedInformerFactory(clientset, 0)
		testSubs := []ObjectSubscriber{
			newTestSubscriber(log.WithField("sub", "sub1")),
		}
		ctrl := New(log, informersFactory, testSubs, version.Version{MinorInt: 22})

		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		errc := make(chan error)
		go func() {
			if err := ctrl.Run(ctx); err != nil {
				errc <- err
			}
		}()

		time.Sleep(100 * time.Millisecond)
		_, err := clientset.AppsV1().DaemonSets(testDs.Namespace).Update(ctx, testDs, metav1.UpdateOptions{})
		r.NoError(err)
		time.Sleep(100 * time.Millisecond)
		err = clientset.AppsV1().DaemonSets(testDs.Namespace).Delete(ctx, testDs.Name, metav1.DeleteOptions{})
		r.NoError(err)

		sub := testSubs[0].(*testSubscriber)
		select {
		case err := <-errc:
			t.Fatal(err)
		case <-time.After(1 * time.Millisecond):
			sub.assertNoUpdates(r)
		}
	})
}

func newTestSubscriber(log logrus.FieldLogger) *testSubscriber {
	return &testSubscriber{
		log:         log,
		addedObjs:   make(map[string]Object),
		updatedObjs: make(map[string]Object),
		deletedObjs: make(map[string]Object),
	}
}

type testSubscriber struct {
	log         logrus.FieldLogger
	mu          sync.Mutex
	addedObjs   map[string]Object
	updatedObjs map[string]Object
	deletedObjs map[string]Object
}

func (t *testSubscriber) assertNoManagedFields(r *require.Assertions) {
	r.Eventually(func() bool {
		t.mu.Lock()
		defer t.mu.Unlock()

		if len(t.addedObjs) == 0 {
			return false
		}
		obj := t.addedObjs["kube-system"]
		return len(obj.GetManagedFields()) == 0
	}, 3*time.Second, 1*time.Millisecond)
}

func (t *testSubscriber) assertNoUpdates(r *require.Assertions) {
	r.Eventually(func() bool {
		t.mu.Lock()
		defer t.mu.Unlock()

		// We need to wait for delete in order to check if update happened or not.
		return len(t.deletedObjs) > 0 && len(t.updatedObjs) == 0
	}, 3*time.Second, 1*time.Millisecond)
}

func (t *testSubscriber) OnAdd(obj Object) {
	t.log.Debug("add")
	t.mu.Lock()
	defer t.mu.Unlock()
	t.addedObjs[obj.GetName()] = obj
}

func (t *testSubscriber) OnUpdate(obj Object) {
	t.log.Debug("update")
	t.mu.Lock()
	defer t.mu.Unlock()
	t.updatedObjs[obj.GetName()] = obj
}

func (t *testSubscriber) OnDelete(obj Object) {
	t.log.Debug("delete")
	t.mu.Lock()
	defer t.mu.Unlock()
	t.deletedObjs[obj.GetName()] = obj
}

func (t *testSubscriber) Run(ctx context.Context) error {
	t.log.Debug("run start")
	defer t.log.Debug("run done")

	for {
		select {
		case <-time.After(1 * time.Millisecond):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (t *testSubscriber) RequiredInformers() []reflect.Type {
	return []reflect.Type{
		reflect.TypeOf(&corev1.Namespace{}),
		reflect.TypeOf(&appsv1.DaemonSet{}),
	}
}
