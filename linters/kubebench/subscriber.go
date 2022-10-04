package kubebench

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/semaphore"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"

	"github.com/castai/sec-agent/castai"
	"github.com/castai/sec-agent/controller"
	"github.com/castai/sec-agent/linters/kubebench/spec"
	"github.com/castai/sec-agent/log"
)

const (
	scanInterval      = 15 * time.Second
	nodeScanTimeout   = 5 * time.Minute
	castAINamespace   = "castai-sec"
	labelJobName      = "job-name"
	maxConcurrentJobs = 5
)

func NewSubscriber(log logrus.FieldLogger, client kubernetes.Interface, provider string, castClient castai.Client, logsReader log.PodLogProvider) controller.ObjectSubscriber {
	return &Subscriber{log: log, client: client, delta: newDeltaState(), provider: provider, castClient: castClient, logsProvider: logsReader}
}

type Subscriber struct {
	log          logrus.FieldLogger
	client       kubernetes.Interface
	castClient   castai.Client
	delta        *nodeDeltaState
	provider     string
	logsProvider log.PodLogProvider
}

func (s *Subscriber) OnAdd(obj controller.Object) {
	node, ok := obj.(*corev1.Node)
	if ok {
		s.delta.upsert(node)
	}
}

func (s *Subscriber) OnUpdate(_ controller.Object) {
	// do not run on updates
}

func (s *Subscriber) OnDelete(obj controller.Object) {
	node, ok := obj.(*corev1.Node)
	if ok {
		s.delta.delete(node)
	}
}

func (s *Subscriber) Run(ctx context.Context) error {
	ticker := time.NewTicker(scanInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			err := s.processCachedNodes(ctx)
			if err != nil && !errors.Is(err, context.Canceled) {
				s.log.Errorf("error linting nodes: %v", err)
			}
		}
	}
}

func (s *Subscriber) processCachedNodes(ctx context.Context) error {
	nodes := s.delta.peek()
	s.log.Infof("linting %d nodes", len(nodes))
	sem := semaphore.NewWeighted(maxConcurrentJobs)
	for _, n := range nodes {
		node := n
		err := sem.Acquire(ctx, 1)
		if err != nil {
			s.log.Errorf("kube-bench semaphore: %v", err)
			continue
		}
		go func() {
			defer sem.Release(1)
			ctx, cancel := context.WithTimeout(ctx, nodeScanTimeout)
			defer cancel()
			err = s.lintNode(ctx, &node)
			if err != nil {
				s.log.Errorf("kube-bench: %v", err)
				return
			}
			s.delta.delete(&node)
		}()
	}
	if err := sem.Acquire(ctx, maxConcurrentJobs); err != nil {
		return err
	}

	return nil
}

func (s *Subscriber) RequiredInformers() []reflect.Type {
	return []reflect.Type{reflect.TypeOf(&corev1.Node{})}
}

func (s *Subscriber) lintNode(ctx context.Context, node *corev1.Node) error {
	jobName := "kube-bench-node-" + node.GetName()
	err := s.client.BatchV1().Jobs(castAINamespace).Delete(ctx, jobName, metav1.DeleteOptions{
		PropagationPolicy: lo.ToPtr(metav1.DeletePropagationBackground),
	})
	if err != nil && !k8serrors.IsNotFound(err) {
		s.log.WithError(err).Errorf("can not delete job %q", jobName)
		return err
	}

	kubeBenchPod, err := s.createKubebenchJob(ctx, node, jobName)
	if err != nil {
		return err
	}

	report, err := s.getReportFromLogs(ctx, node, kubeBenchPod.Name)
	if err != nil {
		return err
	}

	err = s.castClient.SendCISReport(ctx, report)
	if err != nil {
		return err
	}

	err = s.deleteJob(ctx, jobName)
	if err != nil {
		s.log.Errorf("failed deleting job %s: %v", jobName, err)
	}

	return nil
}

// We are interested in kube-bench pod succeeding and not the Job
func (s *Subscriber) createKubebenchJob(ctx context.Context, node *corev1.Node, jobName string) (*corev1.Pod, error) {
	specFn := resolveSpec(s.provider, node)

	job, err := s.client.BatchV1().
		Jobs(castAINamespace).
		Create(ctx, specFn(node.GetName(), jobName), metav1.CreateOptions{})
	if err != nil {
		s.log.WithError(err).Error("can not create kube-bench scan job")
		return nil, err
	}
	selector := labels.Set{labelJobName: job.Name}
	var kubeBenchPod *corev1.Pod

	podCtx, cancel := context.WithTimeout(ctx, 1*time.Minute)
	defer cancel()

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

			kubeBenchPod = &pods.Items[0]

			if kubeBenchPod.Status.Phase == corev1.PodFailed {
				return backoff.Permanent(fmt.Errorf("kube-bench failed: %s", kubeBenchPod.Status.Message))
			}

			if kubeBenchPod.Status.Phase == corev1.PodSucceeded {
				return nil
			}

			return fmt.Errorf("unknown err")
		}, backoff.WithContext(backoff.NewConstantBackOff(10*time.Second), podCtx))

	if err != nil {
		return nil, err
	}

	return kubeBenchPod, nil
}

func (s *Subscriber) deleteJob(ctx context.Context, jobName string) error {
	return s.client.BatchV1().Jobs(castAINamespace).Delete(ctx, jobName, metav1.DeleteOptions{})
}

func (s *Subscriber) getReportFromLogs(ctx context.Context, node *corev1.Node, kubeBenchPodName string) (*castai.CustomReport, error) {
	logReader, err := s.logsProvider.GetLogReader(ctx, castAINamespace, kubeBenchPodName)
	if err != nil {
		return nil, err
	}
	defer logReader.Close()

	report, err := io.ReadAll(logReader)
	if err != nil {
		return nil, err
	}

	var customReport castai.CustomReport
	err = jsoniter.Unmarshal(report, &customReport)
	if err != nil {
		return nil, err
	}

	if len(customReport.Controls) == 0 {
		s.log.Infof("no checks found for node: %s", node.Name)
		return nil, nil
	}

	nodeID, err := uuid.Parse(string(node.UID))
	if err != nil {
		return nil, fmt.Errorf("can't parse node UID: %v", err)
	}

	customReport.Node = castai.Node{
		NodeName:   node.Name,
		ResourceID: nodeID,
	}

	return &customReport, nil
}

func resolveSpec(provider string, node *corev1.Node) func(nodeName, jobname string) *batchv1.Job {
	switch provider {
	case "gke":
		return spec.GKE
	case "aks":
		return spec.AKS
	case "eks":
		return spec.EKS
	default:
		labels := node.GetLabels()
		if _, ok := labels["node-role.kubernetes.io/control-plane"]; ok {
			return spec.Master
		}

		return spec.Node
	}
}
