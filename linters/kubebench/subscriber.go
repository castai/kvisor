package kubebench

import (
	"context"
	"reflect"
	"time"

	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/castai/sec-agent/controller"
	"github.com/castai/sec-agent/linters/kubebench/spec"
)

const (
	scanInterval = 15 * time.Second
)

func NewSubscriber(log logrus.FieldLogger, client kubernetes.Interface, provider string) controller.ObjectSubscriber {
	return &Subscriber{log: log, client: client, delta: newDeltaState(), provider: provider}
}

type Subscriber struct {
	log      logrus.FieldLogger
	client   kubernetes.Interface
	delta    *deltaState
	provider string
}

func (s *Subscriber) OnAdd(obj controller.Object) {
	s.delta.upsert(obj)
}

func (s *Subscriber) OnUpdate(_ controller.Object) {
	// do not run on updates
}

func (s *Subscriber) OnDelete(obj controller.Object) {
	s.delta.delete(obj)
}

func (s *Subscriber) Run(ctx context.Context) error {
	ticker := time.NewTicker(scanInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			s.lintNodes(ctx, s.delta.flush())
		}
	}
}

func (s *Subscriber) RequiredInformers() []reflect.Type {
	return []reflect.Type{reflect.TypeOf(&corev1.Node{})}
}

func (s *Subscriber) lintNodes(ctx context.Context, objects []controller.Object) {
	for _, object := range objects {
		node, ok := object.(*corev1.Node)
		if !ok {
			continue
		}

		jobName := "kube-bench-node-" + node.GetName()
		err := s.client.BatchV1().Jobs("castai-sec").Delete(ctx, jobName, metav1.DeleteOptions{
			PropagationPolicy: lo.ToPtr(metav1.DeletePropagationBackground),
		})
		if err != nil && !errors.IsNotFound(err) {
			s.log.WithError(err).Errorf("can not delete job %q", jobName)
			return
		}

		specFn := resolveSpec(s.provider, node)

		_, err = s.client.BatchV1().
			Jobs("castai-sec").
			Create(ctx, specFn(node.GetName(), jobName), metav1.CreateOptions{})
		if err != nil {
			s.log.WithError(err).Error("can not create kube-bench scan job")
			return
		}

		s.log.Infof("job %q created", jobName)
	}
}

func resolveSpec(provider string, nodeObject controller.Object) func(nodeName, jobname string) *batchv1.Job {
	switch provider {
	case "gke":
		return spec.GKE
	case "aks":
		return spec.AKS
	case "eks":
		return spec.EKS
	default:
		labels := nodeObject.GetLabels()
		if _, ok := labels["node-role.kubernetes.io/control-plane"]; ok {
			return spec.Master
		}

		return spec.Node
	}
}
