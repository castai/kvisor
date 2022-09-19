package kubebench

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/google/uuid"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/semaphore"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"

	"github.com/castai/sec-agent/castai"
	"github.com/castai/sec-agent/controller"
	"github.com/castai/sec-agent/linters/kubebench/spec"
)

const (
	scanInterval      = 15 * time.Second
	castAINamespace   = "castai-sec"
	maxConcurrentJobs = 5
)

func NewSubscriber(log logrus.FieldLogger, client kubernetes.Interface, provider string, castClient castai.Client) controller.ObjectSubscriber {
	return &Subscriber{log: log, client: client, delta: newDeltaState(), provider: provider, castClient: castClient}
}

type Subscriber struct {
	log        logrus.FieldLogger
	client     kubernetes.Interface
	castClient castai.Client
	delta      *nodeDeltaState
	provider   string
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
			s.log.Infof("linting nodes")
			objs := s.delta.flush()

			sem := semaphore.NewWeighted(maxConcurrentJobs)
			for _, obj := range objs {
				object := obj
				err := sem.Acquire(ctx, 1)
				if err != nil {
					s.log.Errorf("kube-bench semaphore: %v", err)
				}
				go func() {
					defer sem.Release(1)
					err = s.lintNode(ctx, object)
					if err != nil {
						s.log.Errorf("kube-bench: %v", err)
					}
				}()
			}
			if err := sem.Acquire(ctx, maxConcurrentJobs); err != nil {
				return err
			}
		}
	}
}

func (s *Subscriber) RequiredInformers() []reflect.Type {
	return []reflect.Type{reflect.TypeOf(&corev1.Node{})}
}

func (s *Subscriber) lintNode(ctx context.Context, object controller.Object) error {
	node, ok := object.(*corev1.Node)
	if !ok {
		return fmt.Errorf("provided object is not v1/Node")
	}

	jobName := "kube-bench-node-" + node.GetName()
	err := s.client.BatchV1().Jobs(castAINamespace).Delete(ctx, jobName, metav1.DeleteOptions{
		PropagationPolicy: lo.ToPtr(metav1.DeletePropagationBackground),
	})
	if err != nil && !errors.IsNotFound(err) {
		s.log.WithError(err).Errorf("can not delete job %q", jobName)
		return err
	}

	specFn := resolveSpec(s.provider, node)

	job, err := s.client.BatchV1().
		Jobs(castAINamespace).
		Create(ctx, specFn(node.GetName(), jobName), metav1.CreateOptions{})
	if err != nil {
		s.log.WithError(err).Error("can not create kube-bench scan job")
		return err
	}
	selector := labels.Set{"job-name": job.Name}
	var kubeBenchPod corev1.Pod

	err = backoff.Retry(
		func() error {
			pods, err := s.client.CoreV1().Pods(castAINamespace).List(ctx, metav1.ListOptions{
				LabelSelector: selector.String(),
			})
			if err != nil {
				return err
			}

			if len(pods.Items) < 1 {
				return fmt.Errorf("pod not found")
			}

			kubeBenchPod = pods.Items[0]
			if kubeBenchPod.Status.Phase == corev1.PodFailed {
				return backoff.Permanent(fmt.Errorf("kube-bench failed: %s", kubeBenchPod.Status.Message))
			}

			if kubeBenchPod.Status.Phase == corev1.PodSucceeded {
				return nil
			}

			return fmt.Errorf("unknown err")
		},
		backoff.WithMaxRetries(
			backoff.NewConstantBackOff(time.Second),
			10),
	)
	if err != nil {
		return err
	}

	req := s.client.CoreV1().Pods(castAINamespace).GetLogs(kubeBenchPod.Name, &corev1.PodLogOptions{})
	podLogs, err := req.Stream(ctx)
	if err != nil {
		return fmt.Errorf("error in opening stream: %v", err)
	}

	report, err := io.ReadAll(podLogs)
	if err != nil {
		return err
	}

	var customReport CustomReport
	err = json.Unmarshal(report, &customReport)
	if err != nil {
		return err
	}

	if len(customReport.Controls) == 0 {
		s.log.Infof("no checks found for node: %s", node.Name)
		return nil
	}

	nodeID, err := uuid.Parse(string(node.UID))
	if err != nil {
		return fmt.Errorf("can't parse node UID: %v", err)
	}

	customReport.Node = Node{
		NodeName:   node.Name,
		ResourceID: nodeID,
	}

	reportBytes, err := json.Marshal(report)
	if err != nil {
		s.log.Errorf("marshalling report: %v", err)
	}

	err = s.castClient.SendCISReport(ctx, reportBytes)
	if err != nil {
		return err
	}
	err = podLogs.Close()
	if err != nil {
		return err
	}
	return nil
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
