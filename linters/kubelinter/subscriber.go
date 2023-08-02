package kubelinter

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"

	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"golang.stackrox.io/kube-linter/pkg/lintcontext"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/castai/kvisor/castai"
	"github.com/castai/kvisor/controller"
	"github.com/castai/kvisor/metrics"
)

func NewSubscriber(log logrus.FieldLogger, client castai.Client, linter *Linter) (controller.ObjectSubscriber, error) {
	ctx, cancel := context.WithCancel(context.Background())
	return &Subscriber{
		ctx:    ctx,
		cancel: cancel,
		client: client,
		linter: linter,
		delta:  newDeltaState(),
		log:    log,
	}, nil
}

type Subscriber struct {
	ctx    context.Context
	cancel context.CancelFunc
	client castai.Client
	linter *Linter
	delta  *deltaState
	log    logrus.FieldLogger
}

func (s *Subscriber) RequiredInformers() []reflect.Type {
	return []reflect.Type{
		reflect.TypeOf(&corev1.Pod{}),
		reflect.TypeOf(&corev1.Namespace{}),
		reflect.TypeOf(&corev1.Service{}),
		reflect.TypeOf(&appsv1.Deployment{}),
		reflect.TypeOf(&appsv1.DaemonSet{}),
		reflect.TypeOf(&appsv1.StatefulSet{}),
		reflect.TypeOf(&rbacv1.ClusterRoleBinding{}),
		reflect.TypeOf(&rbacv1.RoleBinding{}),
		reflect.TypeOf(&rbacv1.ClusterRole{}),
		reflect.TypeOf(&rbacv1.Role{}),
		reflect.TypeOf(&networkingv1.NetworkPolicy{}),
		reflect.TypeOf(&networkingv1.Ingress{}),
		reflect.TypeOf(&batchv1.Job{}),
		reflect.TypeOf(&batchv1.CronJob{}),
	}
}

func (s *Subscriber) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(15 * time.Second):
			objects := s.delta.flush()
			if len(objects) > 0 {
				if err := s.lintObjects(objects); err != nil && !errors.Is(err, context.Canceled) {
					s.log.Error(err)

					// put unprocessed objects back to delta queue
					s.delta.insert(objects...)
				}
			}
		}
	}
}

func (s *Subscriber) OnAdd(obj controller.Object) {
	s.modifyDelta(controller.EventAdd, obj)
}

func (s *Subscriber) OnUpdate(newObj, oldObj controller.Object) {
	s.modifyDelta(controller.EventUpdate, newObj)
}

func (s *Subscriber) OnDelete(obj controller.Object) {
	s.modifyDelta(controller.EventDelete, obj)
}

func (s *Subscriber) modifyDelta(event controller.Event, o controller.Object) {
	switch o := o.(type) {
	case *corev1.Pod:
		// Do not process not static pods.
		if !isStandalonePod(o) {
			return
		}
	}

	switch event {
	case controller.EventAdd:
		s.delta.upsert(o)
	case controller.EventUpdate:
		s.delta.upsert(o)
	case controller.EventDelete:
		s.delta.delete(o)
	}
}

func (s *Subscriber) lintObjects(objects []controller.Object) (rerr error) {
	start := time.Now()
	defer func() {
		metrics.IncScansTotal(metrics.ScanTypeLinter, rerr)
		metrics.ObserveScanDuration(metrics.ScanTypeLinter, start)
	}()

	checks, err := s.linter.Run(lo.Map(objects, func(o controller.Object, i int) lintcontext.Object {
		return lintcontext.Object{K8sObject: o}
	}))
	if err != nil {
		return fmt.Errorf("kubelinter failed: %w", err)
	}

	ctx, cancel := context.WithTimeout(s.ctx, time.Second*5)
	defer cancel()

	if err := s.client.SendLinterChecks(ctx, checks); err != nil {
		return fmt.Errorf("can not send kubelinter checks: %w", err)
	}

	s.log.Infof("kubelinter finished, checks: %d", len(checks))
	return nil
}

func isStandalonePod(pod *corev1.Pod) bool {
	if pod.Spec.NodeName == "" {
		return false
	}

	// pod created without parent
	if len(pod.OwnerReferences) == 0 {
		return true
	}

	// static pod
	return strings.HasSuffix(pod.ObjectMeta.Name, pod.Spec.NodeName)
}
