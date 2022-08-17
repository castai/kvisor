package kubelinter

import (
	"context"
	"errors"
	"reflect"
	"strings"

	"github.com/sirupsen/logrus"
	"golang.stackrox.io/kube-linter/pkg/lintcontext"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/client-go/util/workqueue"

	"github.com/castai/sec-agent/controller"
)

var supportedTypes = map[reflect.Type]struct{}{
	reflect.TypeOf(&corev1.Node{}):               {},
	reflect.TypeOf(&corev1.Pod{}):                {},
	reflect.TypeOf(&corev1.Namespace{}):          {},
	reflect.TypeOf(&corev1.Service{}):            {},
	reflect.TypeOf(&rbacv1.ClusterRoleBinding{}): {},
	reflect.TypeOf(&appsv1.Deployment{}):         {},
	reflect.TypeOf(&appsv1.DaemonSet{}):          {},
	reflect.TypeOf(&appsv1.StatefulSet{}):        {},
}

func NewSubscriber(log logrus.FieldLogger) controller.ObjectSubscriber {
	ctx, cancel := context.WithCancel(context.Background())

	linter := New(rules)

	s := &Subscriber{
		ctx:    ctx,
		cancel: cancel,
		queue:  workqueue.NewNamed("castai-sec-agent-kubelinter"),
		linter: linter,
		log:    log,
	}

	go s.loop()

	return s
}

type Subscriber struct {
	ctx    context.Context
	cancel context.CancelFunc
	queue  workqueue.Interface
	linter *Linter
	log    logrus.FieldLogger
}

func (s *Subscriber) Supports(typ reflect.Type) bool {
	_, ok := supportedTypes[typ]
	return ok
}

func (s *Subscriber) Shutdown(shutdownCtx context.Context) error {
	s.queue.ShutDown()

	select {
	case <-s.ctx.Done():
		return nil
	case <-shutdownCtx.Done():
		return errors.New("kubelinter subscriber shutdown timed out")
	}
}

func (s *Subscriber) OnAdd(obj interface{}) {
	s.queueObject(eventAdd, obj)
}

func (s *Subscriber) OnUpdate(_, newObj interface{}) {
	s.queueObject(eventUpdate, newObj)
}

func (s *Subscriber) OnDelete(obj interface{}) {
	s.queueObject(eventDelete, obj)
}

func (s *Subscriber) queueObject(event event, o interface{}) {
	// Map missing metadata since kubernetes client removes object kind and api version information.
	appsV1 := "apps/v1"
	v1 := "v1"
	switch o := o.(type) {
	case *appsv1.Deployment:
		o.Kind = "Deployment"
		o.APIVersion = appsV1
	case *appsv1.StatefulSet:
		o.Kind = "StatefulSet"
		o.APIVersion = appsV1
	case *appsv1.DaemonSet:
		o.Kind = "DaemonSet"
		o.APIVersion = appsV1
	case *corev1.Node:
		o.Kind = "Node"
		o.APIVersion = v1
	case *corev1.Namespace:
		o.Kind = "Namespace"
		o.APIVersion = v1
	case *corev1.Service:
		o.Kind = "Service"
		o.APIVersion = v1
	case *corev1.Pod:
		o.Kind = "Pod"
		o.APIVersion = v1
		// Do not process not static pods.
		if !isStaticPod(o) {
			return
		}
	case *rbacv1.ClusterRoleBinding:
		o.Kind = "ClusterRoleBinding"
		o.APIVersion = "rbac.authorization.k8s.io/v1"
	default:
		return
	}
	// TODO: Add jobs, cronjobs and other resources for kubelinter.

	s.queue.Add(&queueItem{
		obj:   o.(object),
		event: event,
	})
}

func (s *Subscriber) loop() {
	for {
		item, shutdown := s.queue.Get()
		if shutdown {
			s.cancel()
			return
		}

		s.lintItem(item)
	}
}

func (s *Subscriber) lintItem(i interface{}) {
	defer s.queue.Done(i)

	item, ok := i.(*queueItem)
	if !ok {
		s.log.Errorf("queue item is not of type *queueItem")
		return
	}

	if item.event == eventAdd || item.event == eventUpdate {
		checks, err := s.linter.Run([]lintcontext.Object{{K8sObject: item.obj}})
		if err != nil {
			s.log.Errorf("lint failed: %v", err)
			return
		}

		s.log.Infof("lint finished, checks: %d", len(checks))
	}
}

func isStaticPod(pod *corev1.Pod) bool {
	if pod.Spec.NodeName == "" {
		return false
	}
	return strings.HasSuffix(pod.ObjectMeta.Name, pod.Spec.NodeName)
}
