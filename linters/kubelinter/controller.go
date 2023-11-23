package kubelinter

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/castai/kvisor/config"
	batchv1 "k8s.io/api/batch/v1"

	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"golang.stackrox.io/kube-linter/pkg/lintcontext"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/castai/kvisor/castai"
	"github.com/castai/kvisor/kube"
	"github.com/castai/kvisor/metrics"
)

func NewController(log logrus.FieldLogger, cfg config.Linter, client castai.Client, linter *Linter) *Controller {
	return &Controller{
		log:    log,
		cfg:    cfg,
		client: client,
		linter: linter,
		delta:  newDeltaState(),
	}
}

type Controller struct {
	log    logrus.FieldLogger
	cfg    config.Linter
	client castai.Client
	linter *Linter
	delta  *deltaState
}

func (s *Controller) RequiredInformers() []reflect.Type {
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

func (s *Controller) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(s.cfg.ScanInterval):
			objects := s.delta.flush()
			if len(objects) > 0 {
				if err := s.lintObjects(ctx, objects); err != nil && !errors.Is(err, context.Canceled) {
					s.log.Error(err)

					// put unprocessed objects back to delta queue
					s.delta.insert(objects...)
				}
			}
		}
	}
}

func (s *Controller) OnAdd(obj kube.Object) {
	s.modifyDelta(kube.EventAdd, obj)
}

func (s *Controller) OnUpdate(obj kube.Object) {
	s.modifyDelta(kube.EventUpdate, obj)
}

func (s *Controller) OnDelete(obj kube.Object) {
	s.modifyDelta(kube.EventDelete, obj)
}

func (s *Controller) modifyDelta(event kube.Event, o kube.Object) {
	switch o := o.(type) {
	case *corev1.Pod:
		// Do not process not static pods.
		if !isStandalonePod(o) {
			return
		}
	case *batchv1.Job:
		// Skip jobs which belongs to cronjobs etc.
		if !isStandaloneJob(o) {
			return
		}
	}

	switch event {
	case kube.EventAdd:
		s.delta.upsert(o)
	case kube.EventUpdate:
		s.delta.upsert(o)
	case kube.EventDelete:
		s.delta.delete(o)
	}
}

func (s *Controller) lintObjects(ctx context.Context, objects []kube.Object) (rerr error) {
	start := time.Now()
	defer func() {
		metrics.IncScansTotal(metrics.ScanTypeLinter, rerr)
		metrics.ObserveScanDuration(metrics.ScanTypeLinter, start)
	}()

	checks, err := s.linter.Run(lo.Map(objects, func(o kube.Object, i int) lintcontext.Object {
		return lintcontext.Object{K8sObject: o}
	}))
	if err != nil {
		return fmt.Errorf("kubelinter failed: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
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

	// Pod created without parent.
	if len(pod.OwnerReferences) == 0 {
		return true
	}

	// Static pod.
	return strings.HasSuffix(pod.ObjectMeta.Name, pod.Spec.NodeName)
}

func isStandaloneJob(job *batchv1.Job) bool {
	return len(job.OwnerReferences) == 0
}
