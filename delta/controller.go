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
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	"github.com/castai/kvisor/castai"
	"github.com/castai/kvisor/kube"
	"github.com/castai/kvisor/metrics"
)

var scheme = runtime.NewScheme()
var builder = runtime.SchemeBuilder{
	corev1.AddToScheme,
	appsv1.AddToScheme,
	rbacv1.AddToScheme,
	batchv1.AddToScheme,
	autoscalingv1.AddToScheme,
	networkingv1.AddToScheme,
}

func init() {
	utilruntime.Must(builder.AddToScheme(scheme))
}

type castaiClient interface {
	SendDeltaReport(ctx context.Context, report *castai.Delta, opts ...castai.Option) error
}

type Config struct {
	DeltaSyncInterval time.Duration
}

func NewController(
	log logrus.FieldLogger,
	logLevel logrus.Level,
	cfg Config, client castaiClient,
	stateProvider SnapshotProvider,
	k8sVersionMinor int,
	podOwnerGetter podOwnerGetter,
) *Controller {
	ctx, cancel := context.WithCancel(context.Background())

	return &Controller{
		ctx:             ctx,
		cancel:          cancel,
		cfg:             cfg,
		k8sVersionMinor: k8sVersionMinor,
		log:             log.WithField("component", "delta"),
		client:          client,
		delta:           newDelta(log, podOwnerGetter, logLevel, stateProvider),
		initialDelay:    60 * time.Second,
	}
}

type Controller struct {
	ctx             context.Context
	cancel          context.CancelFunc
	log             logrus.FieldLogger
	cfg             Config
	k8sVersionMinor int
	client          castaiClient
	delta           *delta
	mu              sync.RWMutex
	initialized     bool
	initialDelay    time.Duration
}

func (s *Controller) RequiredInformers() []reflect.Type {
	types := []reflect.Type{
		reflect.TypeOf(&corev1.Pod{}),
		reflect.TypeOf(&corev1.Namespace{}),
		reflect.TypeOf(&corev1.Service{}),
		reflect.TypeOf(&corev1.Node{}),
		reflect.TypeOf(&appsv1.Deployment{}),
		reflect.TypeOf(&appsv1.ReplicaSet{}),
		reflect.TypeOf(&appsv1.DaemonSet{}),
		reflect.TypeOf(&appsv1.StatefulSet{}),
		reflect.TypeOf(&rbacv1.ClusterRoleBinding{}),
		reflect.TypeOf(&rbacv1.RoleBinding{}),
		reflect.TypeOf(&rbacv1.ClusterRole{}),
		reflect.TypeOf(&rbacv1.Role{}),
		reflect.TypeOf(&batchv1.Job{}),
		reflect.TypeOf(&networkingv1.Ingress{}),
		reflect.TypeOf(&networkingv1.NetworkPolicy{}),
	}
	if s.k8sVersionMinor >= 21 {
		types = append(types, reflect.TypeOf(&batchv1.CronJob{}))
	} else {
		types = append(types, reflect.TypeOf(&batchv1beta1.CronJob{}))
	}
	return types
}

func (s *Controller) Run(ctx context.Context) error {
	// Wait for initial deltas sync before starting deltas send loop.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(s.initialDelay):
	}

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

func (s *Controller) OnAdd(obj kube.Object) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.delta.add(kube.EventAdd, obj)
}

func (s *Controller) OnUpdate(obj kube.Object) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.delta.add(kube.EventUpdate, obj)
}

func (s *Controller) OnDelete(obj kube.Object) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.delta.add(kube.EventDelete, obj)
}

func (s *Controller) sendDelta(ctx context.Context) (rerr error) {
	s.mu.RLock()
	deltaReq := s.delta.toCASTAIRequest()
	if !s.initialized {
		// subscriber always waits for state to be synced
		deltaReq.FullSnapshot = true
		s.initialized = true
	}
	s.mu.RUnlock()

	if len(deltaReq.Items) == 0 {
		s.log.Debug("skipping delta send, no new items")
		return nil
	}

	s.log.Debugf("sending delta with items[%d]", len(deltaReq.Items))
	if err := s.client.SendDeltaReport(ctx, deltaReq); err != nil {
		return err
	}
	metrics.IncDeltasSentTotal()
	s.log.Infof("delta with items[%d] sent", len(deltaReq.Items))
	s.delta.clear()
	return nil
}
