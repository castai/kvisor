package kube

import (
	"context"
	"net/http"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/uuid"
	batchv1 "k8s.io/api/batch/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/castai/kvisor/version"
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
		testRs := &appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nginx-rs",
				Namespace: "test",
			},
		}
		testPod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nginx-rs-123",
				Namespace: "test",
			},
		}
		clientset := fake.NewSimpleClientset(testNs, testDs, testPod, testRs)
		informersFactory := informers.NewSharedInformerFactory(clientset, 0)
		testSubs := []ObjectSubscriber{
			newTestSubscriber(log.WithField("sub", "sub1")),
			newTestSubscriber(log.WithField("sub", "sub2")),
		}
		ctrl := NewController(log, informersFactory, version.Version{MinorInt: 22})
		ctrl.AddSubscribers(testSubs...)
		ctrl.podsBuffSyncInterval = 1 * time.Millisecond

		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		errc := make(chan error)
		go func() {
			if err := ctrl.Run(ctx, mockManager{}); err != nil {
				errc <- err
			}
		}()

		for i := 0; i < 2; i++ {
			sub := testSubs[i].(*testSubscriber)
			select {
			case err := <-errc:
				t.Fatal(err)
			case <-time.After(100 * time.Millisecond):
				sub.assertObjectMeta(r)
			}
		}
	})

	t.Run("find pod owner", func(t *testing.T) {
		r := require.New(t)

		type testPod struct {
			ownerRef *metav1.OwnerReference
			labels   map[string]string
		}
		createTestPod := func(pod testPod) *corev1.Pod {
			var refs []metav1.OwnerReference
			if pod.ownerRef != nil {
				refs = append(refs, *pod.ownerRef)
			}
			return &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					UID:             types.UID(uuid.New().String()),
					Name:            uuid.New().String(),
					OwnerReferences: refs,
					Labels:          pod.labels,
				},
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
				},
			}
		}

		rsWithDeployment := &appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{
				UID:  types.UID(uuid.New().String()),
				Name: "rs1",
				OwnerReferences: []metav1.OwnerReference{
					{
						UID:  types.UID(uuid.New().String()),
						Kind: "Deployment",
					},
				},
			},
		}

		rsWithoutDeployment := &appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{
				UID:  types.UID(uuid.New().String()),
				Name: "rs2",
			},
		}

		jobManagedByCronjob := &batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{
				UID:  types.UID(uuid.New().String()),
				Name: "job1",
				OwnerReferences: []metav1.OwnerReference{
					{
						UID:  types.UID(uuid.New().String()),
						Kind: "CronJob",
					},
				},
			},
		}

		jobManagedByCustomCrd := &batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{
				UID:  types.UID(uuid.New().String()),
				Name: "job2",
				OwnerReferences: []metav1.OwnerReference{
					{
						UID:  types.UID(uuid.New().String()),
						Kind: "CustomController",
					},
				},
			},
		}

		standaloneJob := &batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{
				UID:  types.UID(uuid.New().String()),
				Name: "job3",
			},
		}

		statefulSet := &appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{
				UID:  types.UID(uuid.New().String()),
				Name: "st1",
			},
		}

		ds := &appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{
				UID:  types.UID(uuid.New().String()),
				Name: "ds",
			},
		}

		dep := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				UID:  types.UID(uuid.New().String()),
				Name: "d1",
			},
			Spec: appsv1.DeploymentSpec{
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"lbl-pod": "pod10",
					},
				},
			},
		}

		// Pods with well known 2 level owners.
		p1 := createTestPod(testPod{ownerRef: nil})
		p2 := createTestPod(testPod{ownerRef: &metav1.OwnerReference{UID: rsWithDeployment.UID, Kind: "ReplicaSet"}})
		p3 := createTestPod(testPod{ownerRef: &metav1.OwnerReference{UID: rsWithoutDeployment.UID, Kind: "ReplicaSet"}})
		p4 := createTestPod(testPod{ownerRef: &metav1.OwnerReference{UID: jobManagedByCronjob.UID, Kind: "Job"}})
		p5 := createTestPod(testPod{ownerRef: &metav1.OwnerReference{UID: standaloneJob.UID, Kind: "Job"}})

		// Create pods with owners containing custom crds.
		customCrdObjectID := types.UID(uuid.New().String())
		p6 := createTestPod(testPod{ownerRef: &metav1.OwnerReference{UID: customCrdObjectID, Kind: "ArgoRollout"}})
		p7 := createTestPod(testPod{ownerRef: &metav1.OwnerReference{UID: jobManagedByCustomCrd.UID, Kind: "Job"}})

		// Pods with daemon set or statefulset.
		p8 := createTestPod(testPod{ownerRef: &metav1.OwnerReference{UID: statefulSet.UID, Kind: "StatefulSet"}})
		p9 := createTestPod(testPod{ownerRef: &metav1.OwnerReference{UID: ds.UID, Kind: "DaemonSet"}})

		// Pod with custom ReplicaSet managed by custom crd and Deployment selector.
		p10 := createTestPod(testPod{
			labels: map[string]string{
				"lbl-pod":     "pod10",
				"more-labels": "here",
			},
			ownerRef: &metav1.OwnerReference{UID: "random", Kind: "ReplicaSet"}},
		)

		clientset := fake.NewSimpleClientset(
			rsWithDeployment,
			rsWithoutDeployment,
			jobManagedByCronjob,
			jobManagedByCustomCrd,
			standaloneJob,
			statefulSet,
			dep,
			p1,
			p2,
			p3,
			p4,
			p5,
			p6,
			p7,
			p8,
			p9,
			p10,
		)
		informersFactory := informers.NewSharedInformerFactory(clientset, 0)

		testSub := newTestSubscriber(log.WithField("sub", "sub1"))
		ctrl := NewController(log, informersFactory, version.Version{MinorInt: 22})
		ctrl.podsBuffSyncInterval = 10 * time.Millisecond
		ctrl.AddSubscribers(testSub)

		errc := make(chan error)
		go func() {
			if err := ctrl.Run(ctx, mockManager{}); err != nil {
				errc <- err
			}
		}()

		// Wait a bit for informers handlers to apply deltas.
		select {
		case err := <-errc:
			t.Fatal(err)
		case <-time.After(100 * time.Millisecond):
			r.Equal(17, testSub.getAddedObjectsCount())
		}

		r.Equal(string(p1.UID), ctrl.GetPodOwnerID(p1))
		r.Equal(string(rsWithDeployment.OwnerReferences[0].UID), ctrl.GetPodOwnerID(p2))
		r.Equal(string(rsWithoutDeployment.UID), ctrl.GetPodOwnerID(p3))
		r.Equal(string(jobManagedByCronjob.OwnerReferences[0].UID), ctrl.GetPodOwnerID(p4))
		r.Equal(string(p6.UID), ctrl.GetPodOwnerID(p6))
		r.Equal(string(jobManagedByCustomCrd.UID), ctrl.GetPodOwnerID(p7))
		r.Equal(string(statefulSet.UID), ctrl.GetPodOwnerID(p8))
		r.Equal(string(ds.UID), ctrl.GetPodOwnerID(p9))
		r.Equal(string(dep.UID), ctrl.GetPodOwnerID(p10))
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

func (t *testSubscriber) getAddedObjectsCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()

	return len(t.addedObjs)
}

func (t *testSubscriber) assertObjectMeta(r *require.Assertions) {
	t.mu.Lock()
	defer t.mu.Unlock()

	r.Len(t.addedObjs, 4)

	ns := t.addedObjs["kube-system"]
	r.Empty(ns.GetManagedFields())

	ds := t.addedObjs["kube-proxy"]
	r.Equal("DaemonSet", ds.(*appsv1.DaemonSet).Kind)

	rs := t.addedObjs["nginx-rs"]
	r.Equal("ReplicaSet", rs.(*appsv1.ReplicaSet).Kind)

	pod := t.addedObjs["nginx-rs-123"]
	r.Equal("Pod", pod.(*corev1.Pod).Kind)
}

func (t *testSubscriber) OnAdd(obj Object) {
	t.log.Debugf("add %s", obj.GetName())
	t.mu.Lock()
	defer t.mu.Unlock()
	t.addedObjs[obj.GetName()] = obj
}

func (t *testSubscriber) OnUpdate(obj Object) {
	t.log.Debugf("update %s", obj.GetName())
	t.mu.Lock()
	defer t.mu.Unlock()
	t.updatedObjs[obj.GetName()] = obj
}

func (t *testSubscriber) OnDelete(obj Object) {
	t.log.Debugf("delete %s", obj.GetName())
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
		reflect.TypeOf(&appsv1.ReplicaSet{}),
		reflect.TypeOf(&appsv1.StatefulSet{}),
		reflect.TypeOf(&appsv1.Deployment{}),
		reflect.TypeOf(&corev1.Pod{}),
		reflect.TypeOf(&corev1.Node{}),
		reflect.TypeOf(&batchv1.Job{}),
	}
}

type mockManager struct{}

func (m mockManager) SetFields(i interface{}) error                                  { return nil }
func (m mockManager) GetConfig() *rest.Config                                        { return nil }
func (m mockManager) GetScheme() *runtime.Scheme                                     { return nil }
func (m mockManager) GetClient() client.Client                                       { return nil }
func (m mockManager) GetFieldIndexer() client.FieldIndexer                           { return nil }
func (m mockManager) GetCache() cache.Cache                                          { return nil }
func (m mockManager) GetEventRecorderFor(name string) record.EventRecorder           { return nil }
func (m mockManager) GetRESTMapper() meta.RESTMapper                                 { return nil }
func (m mockManager) GetAPIReader() client.Reader                                    { return nil }
func (m mockManager) Start(ctx context.Context) error                                { return nil }
func (m mockManager) Add(runnable manager.Runnable) error                            { return nil }
func (m mockManager) AddMetricsExtraHandler(path string, handler http.Handler) error { return nil }
func (m mockManager) AddHealthzCheck(name string, check healthz.Checker) error       { return nil }
func (m mockManager) AddReadyzCheck(name string, check healthz.Checker) error        { return nil }
func (m mockManager) GetWebhookServer() *webhook.Server                              { return &webhook.Server{} }
func (m mockManager) GetLogger() logr.Logger                                         { return logr.Logger{} }

func (m mockManager) GetControllerOptions() v1alpha1.ControllerConfigurationSpec {
	return v1alpha1.ControllerConfigurationSpec{}
}

func (m mockManager) Elected() <-chan struct{} {
	c := make(chan struct{})
	go func() {
		close(c)
	}()
	return c
}
