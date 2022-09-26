package kubelinter

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"golang.stackrox.io/kube-linter/pkg/lintcontext"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/castai/sec-agent/castai"
	"github.com/castai/sec-agent/controller"
	casttypes "github.com/castai/sec-agent/types"
)

var supportedTypes = []reflect.Type{
	reflect.TypeOf(&corev1.Pod{}),
	reflect.TypeOf(&corev1.Namespace{}),
	reflect.TypeOf(&corev1.Service{}),
	reflect.TypeOf(&rbacv1.ClusterRoleBinding{}),
	reflect.TypeOf(&appsv1.Deployment{}),
	reflect.TypeOf(&appsv1.DaemonSet{}),
	reflect.TypeOf(&appsv1.StatefulSet{}),
}

func NewSubscriber(log logrus.FieldLogger, client castai.Client) controller.ObjectSubscriber {
	ctx, cancel := context.WithCancel(context.Background())

	linter := New(lo.Keys(casttypes.LinterRuleMap))

	return &Subscriber{
		ctx:    ctx,
		cancel: cancel,
		client: client,
		linter: linter,
		delta:  newDeltaState(),
		log:    log,
	}
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
	return supportedTypes
}

func (s *Subscriber) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(15 * time.Second):
			objects := s.delta.flush()
			if len(objects) > 0 {
				if err := s.lintObjects(objects); err != nil {
					s.log.Error(err)

					// return unprocessed objects to the delta queue
					for _, obj := range objects {
						s.delta.upsert(obj)
					}
				}
			}
		}
	}
}

func (s *Subscriber) OnAdd(obj controller.Object) {
	s.modifyDelta(controller.EventAdd, obj)
}

func (s *Subscriber) OnUpdate(obj controller.Object) {
	s.modifyDelta(controller.EventUpdate, obj)
}

func (s *Subscriber) OnDelete(obj controller.Object) {
	s.modifyDelta(controller.EventDelete, obj)
}

func (s *Subscriber) modifyDelta(event controller.Event, o controller.Object) {
	switch o := o.(type) {
	case *corev1.Pod:
		// Do not process not static pods.
		if !isStaticPod(o) {
			return
		}
	}
	// TODO: Add jobs, cronjobs and other resources for kubelinter.

	switch event {
	case controller.EventAdd:
		s.delta.upsert(o)
	case controller.EventUpdate:
		s.delta.upsert(o)
	case controller.EventDelete:
		s.delta.delete(o)
	}
}

func (s *Subscriber) lintObjects(objects []controller.Object) error {
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

func isStaticPod(pod *corev1.Pod) bool {
	if pod.Spec.NodeName == "" {
		return false
	}
	return strings.HasSuffix(pod.ObjectMeta.Name, pod.Spec.NodeName)
}
