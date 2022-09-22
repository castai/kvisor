package delta

import (
	"context"
	"reflect"
	"time"

	"github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	"github.com/castai/sec-agent/castai"
	"github.com/castai/sec-agent/controller"
)

var supportedTypes = []reflect.Type{
	reflect.TypeOf(&corev1.Pod{}),
	reflect.TypeOf(&corev1.Namespace{}),
	reflect.TypeOf(&corev1.Service{}),
	reflect.TypeOf(&corev1.Node{}),
	reflect.TypeOf(&appsv1.Deployment{}),
	reflect.TypeOf(&appsv1.DaemonSet{}),
	reflect.TypeOf(&appsv1.StatefulSet{}),
	reflect.TypeOf(&rbacv1.ClusterRoleBinding{}),
	reflect.TypeOf(&batchv1.Job{}),
	reflect.TypeOf(&batchv1.CronJob{}),
}

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
	SendDelta(ctx context.Context, delta *castai.Delta) error
}

type Config struct {
	DeltaSyncInterval time.Duration
}

func NewSubscriber(log logrus.FieldLogger, logLevel logrus.Level, cfg Config, client castaiClient) controller.ObjectSubscriber {
	ctx, cancel := context.WithCancel(context.Background())

	return &Subscriber{
		ctx:    ctx,
		cancel: cancel,
		cfg:    cfg,
		log:    log,
		client: client,
		delta:  newDelta(log, logLevel),
	}
}

type Subscriber struct {
	ctx    context.Context
	cancel context.CancelFunc
	log    logrus.FieldLogger
	cfg    Config
	client castaiClient
	delta  *delta
}

func (s *Subscriber) RequiredInformers() []reflect.Type {
	return supportedTypes
}

func (s *Subscriber) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(s.cfg.DeltaSyncInterval):
			if err := s.sendDelta(ctx); err != nil {
				s.log.Errorf("sending delta: %v", err)
			}
		}
	}
}

func (s *Subscriber) OnAdd(obj controller.Object) {
	s.delta.add(&item{
		object: obj,
		event:  controller.EventAdd,
	})
}

func (s *Subscriber) OnUpdate(obj controller.Object) {
	s.delta.add(&item{
		object: obj,
		event:  controller.EventUpdate,
	})
}

func (s *Subscriber) OnDelete(obj controller.Object) {
	s.delta.add(&item{
		object: obj,
		event:  controller.EventDelete,
	})
}

func (s *Subscriber) sendDelta(ctx context.Context) error {
	if err := s.client.SendDelta(ctx, s.delta.toCASTAIRequest()); err != nil {
		return err
	}
	s.delta.clear()
	return nil
}
