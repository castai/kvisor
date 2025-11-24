package nodecomponentscollector

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"reflect"
	"sync"
	"time"

	"github.com/castai/kvisor/cmd/controller/kube"
	"github.com/castai/kvisor/pkg/castai"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/cenkalti/backoff/v5"
	"github.com/samber/lo"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

const (
	nodeScanTimeout   = 5 * time.Minute
	labelJobName      = "job-name"
	maxConcurrentJobs = 1
	componentName     = "node-components-collector"
)

type kubeController interface {
	GetKvisorAgentImageDetails() (kube.ImageDetails, error)
}

type Config struct {
	Enabled            bool          `json:"enabled"`
	ScanInterval       time.Duration `validate:"required" json:"scanInterval"`
	ServiceAccountName string        `validate:"required" json:"serviceAccount"`
	JobNamespace       string        `validate:"required" json:"jobNamespace"`
}

func NewController(
	log *logging.Logger,
	client kubernetes.Interface,
	cfg Config,
	castaiCfg castai.Config,
) *Controller {
	return &Controller{
		log:                           log.WithField("component", componentName),
		client:                        client,
		cfg:                           cfg,
		castAIConfig:                  castaiCfg,
		nodes:                         newDeltaState(),
		finishedJobDeleteWaitDuration: 10 * time.Second,
	}
}

type Controller struct {
	log                           *logging.Logger
	client                        kubernetes.Interface
	cfg                           Config
	castAIConfig                  castai.Config
	nodes                         *nodeDeltaState
	kubeController                kubeController
	finishedJobDeleteWaitDuration time.Duration
}

func (c *Controller) RequiredTypes() []reflect.Type {
	return []reflect.Type{
		reflect.TypeOf(&corev1.Node{}),
	}
}

func (c *Controller) OnAdd(obj kube.Object) {
	node, ok := obj.(*corev1.Node)
	if ok && isNodeReady(node) {
		c.nodes.upsert(node)
	}
}

func (c *Controller) OnUpdate(obj kube.Object) {
	c.OnAdd(obj)
}

func (c *Controller) OnDelete(obj kube.Object) {
	node, ok := obj.(*corev1.Node)
	if ok {
		c.nodes.delete(node)
	}
}

func (c *Controller) Run(ctx context.Context) error {
	c.log.Info("running")
	defer c.log.Infof("stopping")

	// add existing nodes
	nodes, err := c.client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list nodes: %w", err)
	}
	for _, node := range nodes.Items {
		c.OnAdd(&node)
	}

	ticker := time.NewTicker(c.cfg.ScanInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			err := c.process(ctx)
			if err != nil && !errors.Is(err, context.Canceled) {
				c.log.Errorf("run node components collector: %v", err)
			}
		}
	}
}

func (c *Controller) process(ctx context.Context) (rerr error) {
	nodes := c.nodes.peek()
	var nodeJobs []*nodeJob
	for _, nodeJob := range nodes {
		if nodeJob.ready() && len(nodeJob.node.Spec.Taints) == 0 {
			nodeJobs = append(nodeJobs, nodeJob)
			if len(nodeJobs) == maxConcurrentJobs {
				break
			}
		}
	}
	if len(nodeJobs) == 0 {
		return nil
	}

	c.log.Infof("processing node components collector")
	defer c.log.Info("processing node components collector done")
	var wg sync.WaitGroup
	for _, n := range nodeJobs {
		job := n
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(ctx, nodeScanTimeout)
			defer cancel()
			err := c.scrapNodeConfigs(ctx, job.node)
			if err != nil {
				c.log.WithField("node", job.node.Name).Errorf("node components collector: %v", err)
				job.setFailed()
				return
			}
			// c.delta.delete(job.node)
		}()
	}

	wg.Wait()
	return nil
}

func (c *Controller) RequiredInformers() []reflect.Type {
	return []reflect.Type{reflect.TypeOf(&corev1.Node{})}
}

func (c *Controller) scrapNodeConfigs(ctx context.Context, node *corev1.Node) (rerr error) {
	c.log.Debugf("starting node components collector job for node=%s", node.Name)
	jobName := generateJobName(node.GetName())

	err := c.deleteJob(ctx, jobName)
	if err != nil && !k8serrors.IsNotFound(err) {
		c.log.Errorf("can not delete job %q: %v", jobName, err)
		return err
	}

	if err == nil {
		err = c.waitJobDeleted(ctx, jobName)
		if err != nil {
			return err
		}
	}

	_, err = c.createConfigScrapperJob(ctx, node, jobName)

	if c.finishedJobDeleteWaitDuration != 0 {
		go func() {
			// Wait some time before deleting job. This is useful for observability and e2e tests.
			select {
			case <-ctx.Done():
				return
			case <-time.After(c.finishedJobDeleteWaitDuration):
			}
			err = c.deleteJob(ctx, jobName)
			if err != nil {
				c.log.Errorf("failed deleting job %s: %v", jobName, err)
			}
		}()
	} else {
		err = c.deleteJob(ctx, jobName)
		if err != nil {
			c.log.Errorf("failed deleting job %s: %v", jobName, err)
		}
	}

	return nil
}

// We are interested in job pod succeeding and not the Job
func (c *Controller) createConfigScrapperJob(ctx context.Context, node *corev1.Node, jobName string) (*corev1.Pod, error) {
	jobSpec := generateJobSpec(c.castAIConfig, jobName, string(node.GetUID()), node.GetName(), c.cfg.ServiceAccountName)

	// Set job image
	imageDetails, err := c.kubeController.GetKvisorAgentImageDetails()
	if err != nil {
		return nil, fmt.Errorf("kvisor image details not found: %w", err)
	}
	cont := jobSpec.Spec.Template.Spec.Containers[0]
	cont.Image = imageDetails.ScannerImageName
	cont.ImagePullPolicy = corev1.PullIfNotPresent
	jobSpec.Spec.Template.Spec.Containers[0] = cont
	jobSpec.Spec.Template.Spec.ImagePullSecrets = imageDetails.ImagePullSecrets

	job, err := c.client.BatchV1().
		Jobs(c.cfg.JobNamespace).
		Create(ctx, jobSpec, metav1.CreateOptions{})
	if err != nil {
		c.log.Errorf("can not create node components collector job: %v", err)
		return nil, err
	}
	selector := labels.Set{labelJobName: job.Name}
	var kubeBenchPod *corev1.Pod

	podCtx, cancel := context.WithTimeout(ctx, 1*time.Minute)
	defer cancel()

	_, err = backoff.Retry(podCtx,
		func() (any, error) {
			pods, err := c.client.CoreV1().Pods(c.cfg.JobNamespace).List(ctx, metav1.ListOptions{
				LabelSelector: selector.String(),
			})
			if err != nil {
				return nil, err
			}

			if len(pods.Items) < 1 {
				return nil, fmt.Errorf("pod not found")
			}

			kubeBenchPod = &pods.Items[0]

			if kubeBenchPod.Status.Phase == corev1.PodFailed {
				return nil, backoff.Permanent(fmt.Errorf("node components collector failed: %s", kubeBenchPod.Status.Message))
			}

			if kubeBenchPod.Status.Phase == corev1.PodSucceeded {
				return nil, nil
			}

			return nil, fmt.Errorf("unknown err")
		}, backoff.WithBackOff(backoff.NewConstantBackOff(10*time.Second)))

	if err != nil {
		return nil, err
	}

	return kubeBenchPod, nil
}

func (c *Controller) deleteJob(ctx context.Context, jobName string) error {
	return c.client.BatchV1().Jobs(c.cfg.JobNamespace).Delete(ctx, jobName, metav1.DeleteOptions{
		GracePeriodSeconds: lo.ToPtr(int64(0)),
		PropagationPolicy:  lo.ToPtr(metav1.DeletePropagationBackground),
	})
}

func (c *Controller) waitJobDeleted(ctx context.Context, jobName string) error {
	deleteCtx, cancel := context.WithTimeout(ctx, 1*time.Minute)
	defer cancel()
	_, err := backoff.Retry(deleteCtx,
		func() (any, error) {
			_, err := c.client.BatchV1().Jobs(c.cfg.JobNamespace).Get(deleteCtx, jobName, metav1.GetOptions{})
			if err != nil {
				if k8serrors.IsNotFound(err) {
					return nil, nil
				}

				return nil, backoff.Permanent(err)
			}

			return nil, fmt.Errorf("job not yet deleted")
		}, backoff.WithBackOff(backoff.NewConstantBackOff(10*time.Second)))

	return err
}

func generateJobName(nodeName string) string {
	h := fnv.New32a()
	h.Write([]byte(nodeName))
	return fmt.Sprintf("castai-%s-%d", componentName, h.Sum32())
}

func isNodeReady(n *corev1.Node) bool {
	if len(n.Status.Conditions) == 0 {
		return false
	}
	lastCondition := n.Status.Conditions[len(n.Status.Conditions)-1]
	return lastCondition.Type == corev1.NodeReady && lastCondition.Status == corev1.ConditionTrue
}
