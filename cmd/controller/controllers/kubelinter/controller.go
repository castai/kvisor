package kubelinter

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/controller/kube"
	"github.com/castai/logging"
	"google.golang.org/grpc"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/samber/lo"
	"golang.stackrox.io/kube-linter/pkg/lintcontext"
	corev1 "k8s.io/api/core/v1"
)

type castaiClient interface {
	KubeLinterReportIngest(ctx context.Context, in *castaipb.KubeLinterReport, opts ...grpc.CallOption) (*castaipb.KubeLinterReportIngestResponse, error)
}

type Config struct {
	Enabled      bool          `json:"enabled"`
	ScanInterval time.Duration `validate:"required" json:"scanInterval"`
	InitDelay    time.Duration `json:"initDelay"`
}

func NewController(log *logging.Logger, cfg Config, linter *Linter, castaiClient castaiClient) *Controller {
	return &Controller{
		log:    log.WithField("component", "kubelinter"),
		cfg:    cfg,
		linter: linter,
		client: castaiClient,
		delta:  newDeltaState(),
	}
}

type Controller struct {
	log    *logging.Logger
	cfg    Config
	linter *Linter
	client castaiClient
	delta  *deltaState
}

func (c *Controller) RequiredTypes() []reflect.Type {
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

func (c *Controller) Run(ctx context.Context) error {
	c.log.Info("running")
	defer c.log.Infof("stopping")

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(c.cfg.InitDelay):
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(c.cfg.ScanInterval):
			objects := c.delta.flush()
			if len(objects) > 0 {
				if err := c.lintObjects(ctx, objects); err != nil && !errors.Is(err, context.Canceled) {
					c.log.Error(err.Error())

					// put unprocessed objects back to delta queue
					c.delta.insert(objects...)
				}
			}
		}
	}
}

func (c *Controller) OnAdd(obj kube.Object) {
	c.modifyDelta(kube.EventAdd, obj)
}

func (c *Controller) OnUpdate(obj kube.Object) {
	c.modifyDelta(kube.EventUpdate, obj)
}

func (c *Controller) OnDelete(obj kube.Object) {
	c.modifyDelta(kube.EventDelete, obj)
}

func (c *Controller) modifyDelta(event kube.EventType, o kube.Object) {
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
		c.delta.upsert(o)
	case kube.EventUpdate:
		c.delta.upsert(o)
	case kube.EventDelete:
		c.delta.delete(o)
	}
}

func (c *Controller) lintObjects(ctx context.Context, objects []kube.Object) (rerr error) {
	checks, err := c.linter.Run(lo.Map(objects, func(o kube.Object, i int) lintcontext.Object {
		return lintcontext.Object{K8sObject: o}
	}))
	if err != nil {
		return fmt.Errorf("kubelinter failed: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	pbReport := &castaipb.KubeLinterReport{
		Checks: lo.Map(checks, func(item LinterCheck, index int) *castaipb.KubeLinterCheck {
			var passed, failed uint64
			if item.Passed != nil {
				passed = uint64(*item.Passed) // nolint:gosec
			}
			if item.Failed != nil {
				failed = uint64(*item.Failed) // nolint:gosec
			}
			return &castaipb.KubeLinterCheck{
				ResourceUid: item.ResourceID,
				Passed:      passed,
				Failed:      failed,
			}
		}),
	}

	if _, err := c.client.KubeLinterReportIngest(ctx, pbReport); err != nil {
		return fmt.Errorf("can not send kubelinter checks: %w", err)
	}

	c.log.Infof("kubelinter finished, checks: %d", len(checks))
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
	return strings.HasSuffix(pod.Name, pod.Spec.NodeName)
}

func isStandaloneJob(job *batchv1.Job) bool {
	return len(job.OwnerReferences) == 0
}
