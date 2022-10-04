package delta

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	"github.com/castai/sec-agent/castai"
	"github.com/castai/sec-agent/controller"
)

var scheme = runtime.NewScheme()
var builder = runtime.SchemeBuilder{
	corev1.AddToScheme,
	appsv1.AddToScheme,
	rbacv1.AddToScheme,
	batchv1.AddToScheme,
	autoscalingv1.AddToScheme,
}

func init() {
	utilruntime.Must(builder.AddToScheme(scheme))
}

type castaiClient interface {
	SendDeltaReport(ctx context.Context, report *castai.Delta) error
}

type Config struct {
	DeltaSyncInterval time.Duration
}

func NewSubscriber(log logrus.FieldLogger, logLevel logrus.Level, cfg Config, client castaiClient, k8sVersionMinor int) controller.ObjectSubscriber {
	ctx, cancel := context.WithCancel(context.Background())

	return &Subscriber{
		ctx:             ctx,
		cancel:          cancel,
		cfg:             cfg,
		k8sVersionMinor: k8sVersionMinor,
		log:             log,
		client:          client,
		delta:           newDelta(log, logLevel),
	}
}

type Subscriber struct {
	ctx             context.Context
	cancel          context.CancelFunc
	log             logrus.FieldLogger
	cfg             Config
	k8sVersionMinor int
	client          castaiClient
	delta           *delta
	mu              sync.RWMutex
}

func (s *Subscriber) RequiredInformers() []reflect.Type {
	types := []reflect.Type{
		reflect.TypeOf(&corev1.Pod{}),
		reflect.TypeOf(&corev1.Namespace{}),
		reflect.TypeOf(&corev1.Service{}),
		reflect.TypeOf(&corev1.Node{}),
		reflect.TypeOf(&appsv1.Deployment{}),
		reflect.TypeOf(&appsv1.DaemonSet{}),
		reflect.TypeOf(&appsv1.StatefulSet{}),
		reflect.TypeOf(&rbacv1.ClusterRoleBinding{}),
		reflect.TypeOf(&rbacv1.RoleBinding{}),
		reflect.TypeOf(&rbacv1.ClusterRole{}),
		reflect.TypeOf(&rbacv1.Role{}),
		reflect.TypeOf(&batchv1.Job{}),
	}
	if s.k8sVersionMinor >= 21 {
		types = append(types, reflect.TypeOf(&batchv1.CronJob{}))
	} else {
		types = append(types, reflect.TypeOf(&batchv1beta1.CronJob{}))
	}
	return types
}

func (s *Subscriber) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(s.cfg.DeltaSyncInterval):
			if err := s.sendDelta(ctx); err != nil && !errors.Is(err, context.Canceled) {
				s.log.Errorf("sending delta: %v", err)
			}
		}
	}
}

func (s *Subscriber) OnAdd(obj controller.Object) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.delta.add(controller.EventAdd, obj)
}

func (s *Subscriber) OnUpdate(obj controller.Object) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.delta.add(controller.EventUpdate, obj)
}

func (s *Subscriber) OnDelete(obj controller.Object) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.delta.add(controller.EventDelete, obj)
}

func (s *Subscriber) sendDelta(ctx context.Context) error {
	s.mu.RLock()
	deltaReq := s.delta.toCASTAIRequest()
	s.mu.RUnlock()

	if len(deltaReq.Items) == 0 {
		s.log.Debug("skipping delta send, no new items")
		return nil
	}

	s.log.Debugf("sending delta with items[%d]", len(deltaReq.Items))
	if err := s.client.SendDeltaReport(ctx, deltaReq); err != nil {
		return err
	}
	s.log.WithField("full_snapshot", "todo").Infof("delta with items[%d] sent", len(deltaReq.Items))
	s.delta.clear()
	return nil
}
