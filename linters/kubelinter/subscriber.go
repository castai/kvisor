package kubelinter

import (
	"context"
	"reflect"
	"strings"
	"time"

	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"golang.stackrox.io/kube-linter/pkg/lintcontext"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/castai/sec-agent/controller"
)

var supportedTypes = []reflect.Type{
	//reflect.TypeOf(&corev1.Node{}),
	reflect.TypeOf(&corev1.Pod{}),
	reflect.TypeOf(&corev1.Namespace{}),
	reflect.TypeOf(&corev1.Service{}),
	reflect.TypeOf(&rbacv1.ClusterRoleBinding{}),
	reflect.TypeOf(&appsv1.Deployment{}),
	reflect.TypeOf(&appsv1.DaemonSet{}),
	reflect.TypeOf(&appsv1.StatefulSet{}),
}

func NewSubscriber(log logrus.FieldLogger) controller.ObjectSubscriber {
	ctx, cancel := context.WithCancel(context.Background())

	linter := New(rules)

	return &Subscriber{
		ctx:    ctx,
		cancel: cancel,
		linter: linter,
		delta:  newDeltaState(),
		log:    log,
	}
}

type Subscriber struct {
	ctx    context.Context
	cancel context.CancelFunc
	linter *Linter
	delta  *deltaState
	log    logrus.FieldLogger
}

func (s *Subscriber) RequiredInformers() []reflect.Type {
	return supportedTypes
}

func (s *Subscriber) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(15 * time.Second):
			s.lintObjects(s.delta.flush())
		}
	}
}

func (s *Subscriber) Supports(typ reflect.Type) bool {
	for i := range supportedTypes {
		if supportedTypes[i] == typ {
			return true
		}
	}

	return false
}

func (s *Subscriber) OnAdd(obj interface{}) {
	s.modifyDelta(eventAdd, obj)
}

func (s *Subscriber) OnUpdate(_, newObj interface{}) {
	s.modifyDelta(eventUpdate, newObj)
}

func (s *Subscriber) OnDelete(obj interface{}) {
	s.modifyDelta(eventDelete, obj)
}

func (s *Subscriber) modifyDelta(event event, o interface{}) {
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

	switch event {
	case eventAdd:
		s.delta.add(o.(object))
	case eventUpdate:
		s.delta.add(o.(object))
	case eventDelete:
		s.delta.delete(o.(object))
	}
}

func (s *Subscriber) lintObjects(objects []object) {
	checks, err := s.linter.Run(lo.Map(objects, func(o object, i int) lintcontext.Object {
		return lintcontext.Object{K8sObject: o}
	}))
	if err != nil {
		s.log.Errorf("lint failed: %v", err)
		return
	}

	s.log.Infof("lint finished, checks: %d", len(checks))
}

func isStaticPod(pod *corev1.Pod) bool {
	if pod.Spec.NodeName == "" {
		return false
	}
	return strings.HasSuffix(pod.ObjectMeta.Name, pod.Spec.NodeName)
}
