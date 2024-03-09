package kubebench

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"hash/maphash"
	"io"
	"reflect"
	"sync"
	"time"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/controller/kube"
	"github.com/castai/kvisor/cmd/controller/state/kubebench/spec"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/cenkalti/backoff/v4"
	"github.com/google/uuid"
	lru "github.com/hashicorp/golang-lru"
	jsoniter "github.com/json-iterator/go"
	"github.com/samber/lo"
	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding/gzip"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

type castaiClient interface {
	KubeBenchReportIngest(ctx context.Context, in *castaipb.KubeBenchReport, opts ...grpc.CallOption) (*castaipb.KubeBenchReportIngestResponse, error)
}

const (
	nodeScanTimeout   = 5 * time.Minute
	labelJobName      = "job-name"
	maxConcurrentJobs = 1
)

type kubeController interface {
	GetKvisorAgentImageDetails() (kube.ImageDetails, bool)
}

type Config struct {
	Enabled            bool
	Force              bool
	ScanInterval       time.Duration `validate:"required"`
	JobImagePullPolicy string
	CloudProvider      string
	JobNamespace       string
}

func NewController(
	log *logging.Logger,
	client kubernetes.Interface,
	cfg Config,
	castClient castaiClient,
	logsReader kube.PodLogProvider,
	kubeController kubeController,
	scannedNodes []string,
) *Controller {
	nodeCache, _ := lru.New(1000)
	for _, node := range scannedNodes {
		nodeCache.Add(node, struct{}{})
	}

	return &Controller{
		log:                           log.WithField("component", "kubebench"),
		client:                        client,
		cfg:                           cfg,
		delta:                         newDeltaState(),
		castClient:                    castClient,
		logsProvider:                  logsReader,
		kubeController:                kubeController,
		scannedNodes:                  nodeCache,
		finishedJobDeleteWaitDuration: 10 * time.Second,
		kubeBenchReportsCache:         map[uint64]*castaipb.KubeBenchReport{},
	}
}

type Controller struct {
	log                           *logging.Logger
	client                        kubernetes.Interface
	cfg                           Config
	castClient                    castaiClient
	delta                         *nodeDeltaState
	logsProvider                  kube.PodLogProvider
	kubeController                kubeController
	finishedJobDeleteWaitDuration time.Duration
	scannedNodes                  *lru.Cache
	// After job finishes with store report in memory grouped by similar nodes.
	// This allows to reduce number of jobs since we near identical reports.
	kubeBenchReportsCache   map[uint64]*castaipb.KubeBenchReport
	kubeBenchReportsCacheMu sync.Mutex
}

func (c *Controller) OnAdd(obj kube.Object) {
	node, ok := obj.(*corev1.Node)
	if ok {
		_, scanned := c.scannedNodes.Get(string(node.GetUID()))
		if isNodeReady(node) && !scanned {
			c.delta.upsert(node)
		}
	}
}

func (c *Controller) OnUpdate(obj kube.Object) {
	c.OnAdd(obj)
}

func (c *Controller) OnDelete(obj kube.Object) {
	node, ok := obj.(*corev1.Node)
	if ok {
		c.delta.delete(node)
		c.scannedNodes.Remove(string(obj.GetUID()))
	}
}

func (c *Controller) Run(ctx context.Context) error {
	c.log.Info("running")
	defer c.log.Infof("stopping")

	ticker := time.NewTicker(c.cfg.ScanInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			err := c.process(ctx)
			if err != nil && !errors.Is(err, context.Canceled) {
				c.log.Errorf("error linting nodes: %v", err)
			}
		}
	}
}

func (c *Controller) process(ctx context.Context) (rerr error) {
	nodes := c.findNodesForScan()
	if len(nodes) == 0 {
		return nil
	}

	c.log.Infof("processing kube-bench")
	defer c.log.Info("processing kube-bench done")
	var wg sync.WaitGroup
	for _, n := range nodes {
		job := n
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(ctx, nodeScanTimeout)
			defer cancel()
			err := c.lintNode(ctx, job.node)
			if err != nil {
				c.log.WithField("node", job.node.Name).Errorf("kube-bench: %v", err)
				job.setFailed()
				return
			}
			c.delta.delete(job.node)
		}()
	}

	wg.Wait()
	return nil
}

func (c *Controller) findNodesForScan() []*nodeJob {
	nodes := c.delta.peek()
	var res []*nodeJob
	for _, nodeJob := range nodes {
		if nodeJob.ready() && len(nodeJob.node.Spec.Taints) == 0 {
			res = append(res, nodeJob)
			if len(res) == maxConcurrentJobs {
				break
			}
		}
	}
	return res
}

func (c *Controller) RequiredInformers() []reflect.Type {
	return []reflect.Type{reflect.TypeOf(&corev1.Node{})}
}

func (c *Controller) lintNode(ctx context.Context, node *corev1.Node) (rerr error) {
	// Check if node is in node group for already scanned jobs.
	// In found we can skip job scheduling.
	if cachedReport, found := c.findScannedReport(node); found {
		report := &castaipb.KubeBenchReport{
			Controls: cachedReport.Controls,
			Node: &castaipb.KubeBenchNode{
				NodeName:    node.Name,
				ResourceUid: string(node.UID),
			},
		}
		_, err := c.castClient.KubeBenchReportIngest(ctx, report)
		if err != nil {
			return err
		}

		c.scannedNodes.Add(string(node.UID), struct{}{})
		return nil
	}

	c.log.Debugf("starting kube-bench lint for node=%s", node.Name)
	jobName := generateName(node.GetName())
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

	kubeBenchPod, err := c.createKubebenchJob(ctx, node, jobName)
	if err != nil {
		return err
	}
	report, err := c.getReportFromLogs(ctx, node, kubeBenchPod.Name)
	if err != nil {
		return fmt.Errorf("reading kube-bench report from pod logs: %w", err)
	}
	c.addReportToCache(node, report)
	_, err = c.castClient.KubeBenchReportIngest(ctx, report, grpc.UseCompressor(gzip.Name))
	if err != nil {
		return err
	}

	c.scannedNodes.Add(string(node.UID), struct{}{})
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

func (c *Controller) findScannedReport(n *corev1.Node) (*castaipb.KubeBenchReport, bool) {
	c.kubeBenchReportsCacheMu.Lock()
	defer c.kubeBenchReportsCacheMu.Unlock()

	key := getNodeGroupKey(n)
	report, found := c.kubeBenchReportsCache[key]
	return report, found
}

func (c *Controller) addReportToCache(n *corev1.Node, report *castaipb.KubeBenchReport) {
	c.kubeBenchReportsCacheMu.Lock()
	defer c.kubeBenchReportsCacheMu.Unlock()

	key := getNodeGroupKey(n)
	c.kubeBenchReportsCache[key] = report
}

// We are interested in kube-bench pod succeeding and not the Job
func (c *Controller) createKubebenchJob(ctx context.Context, node *corev1.Node, jobName string) (*corev1.Pod, error) {
	specFn := resolveSpec(c.cfg.CloudProvider, node)
	jobSpec := specFn(node.GetName(), jobName)

	// Set image.
	imageDetails, found := c.kubeController.GetKvisorAgentImageDetails()
	if !found {
		return nil, errors.New("kvisor image details not found")
	}
	cont := jobSpec.Spec.Template.Spec.Containers[0]
	cont.Image = imageDetails.ImageName
	cont.ImagePullPolicy = corev1.PullPolicy(c.cfg.JobImagePullPolicy)
	jobSpec.Spec.Template.Spec.Containers[0] = cont
	jobSpec.Spec.Template.Spec.ImagePullSecrets = imageDetails.ImagePullSecrets

	job, err := c.client.BatchV1().
		Jobs(c.cfg.JobNamespace).
		Create(ctx, jobSpec, metav1.CreateOptions{})
	if err != nil {
		c.log.Errorf("can not create kube-bench scan job: %v", err)
		return nil, err
	}
	selector := labels.Set{labelJobName: job.Name}
	var kubeBenchPod *corev1.Pod

	podCtx, cancel := context.WithTimeout(ctx, 1*time.Minute)
	defer cancel()

	err = backoff.Retry(
		func() error {
			pods, err := c.client.CoreV1().Pods(c.cfg.JobNamespace).List(ctx, metav1.ListOptions{
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

func (c *Controller) deleteJob(ctx context.Context, jobName string) error {
	return c.client.BatchV1().Jobs(c.cfg.JobNamespace).Delete(ctx, jobName, metav1.DeleteOptions{
		GracePeriodSeconds: lo.ToPtr(int64(0)),
		PropagationPolicy:  lo.ToPtr(metav1.DeletePropagationBackground),
	})
}

func (c *Controller) waitJobDeleted(ctx context.Context, jobName string) error {
	deleteCtx, cancel := context.WithTimeout(ctx, 1*time.Minute)
	defer cancel()
	return backoff.Retry(
		func() error {
			_, err := c.client.BatchV1().Jobs(c.cfg.JobNamespace).Get(deleteCtx, jobName, metav1.GetOptions{})
			if err != nil {
				if k8serrors.IsNotFound(err) {
					return nil
				}

				return backoff.Permanent(err)
			}

			return fmt.Errorf("job not yet deleted")
		}, backoff.WithContext(backoff.NewConstantBackOff(10*time.Second), deleteCtx))
}

func (c *Controller) getReportFromLogs(ctx context.Context, node *corev1.Node, kubeBenchPodName string) (*castaipb.KubeBenchReport, error) {
	logReader, err := c.logsProvider.GetLogReader(ctx, c.cfg.JobNamespace, kubeBenchPodName)
	if err != nil {
		return nil, err
	}
	defer logReader.Close()

	report, err := io.ReadAll(logReader)
	if err != nil {
		return nil, err
	}

	var customReport KubeBenchReport
	err = jsoniter.Unmarshal(report, &customReport)
	if err != nil {
		return nil, err
	}

	if len(customReport.Controls) == 0 {
		c.log.Infof("no checks found for node: %s", node.Name)
		return nil, nil
	}

	nodeID, err := uuid.Parse(string(node.UID))
	if err != nil {
		return nil, fmt.Errorf("can't parse node UID: %w", err)
	}

	res := &castaipb.KubeBenchReport{
		Controls: lo.Map(customReport.Controls, func(item *Controls, index int) *castaipb.KubeBenchControls {
			return &castaipb.KubeBenchControls{
				Version: item.Version,
				Groups: lo.Map(item.Groups, func(item *Group, index int) *castaipb.KubeBenchGroup {
					return &castaipb.KubeBenchGroup{
						Checks: lo.Map(item.Checks, func(item *Check, index int) *castaipb.KubeBenchCheck {
							return &castaipb.KubeBenchCheck{
								Id:       item.ID,
								Text:     item.Text,
								TestInfo: item.TestInfo,
								State:    string(item.State),
							}
						}),
					}
				}),
			}
		}),
		Node: &castaipb.KubeBenchNode{
			NodeName:    node.Name,
			ResourceUid: nodeID.String(),
		},
	}

	return res, nil
}

func generateName(nodeName string) string {
	h := fnv.New32a()
	h.Write([]byte(nodeName))
	return fmt.Sprintf("castai-kube-bench-%d", h.Sum32())
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

func isNodeReady(n *corev1.Node) bool {
	if len(n.Status.Conditions) == 0 {
		return false
	}
	lastCondition := n.Status.Conditions[len(n.Status.Conditions)-1]
	return lastCondition.Type == corev1.NodeReady && lastCondition.Status == corev1.ConditionTrue
}

var nodeGroupsHashSeed maphash.Seed

func init() {
	nodeGroupsHashSeed = maphash.MakeSeed()
}

// getNodeGroupKey creates hash for nodes group.
// Thread safe.
func getNodeGroupKey(n *corev1.Node) uint64 {
	var hash maphash.Hash
	hash.SetSeed(nodeGroupsHashSeed)
	if v, found := n.Labels["provisioner.cast.ai/node-configuration-name"]; found {
		_, _ = hash.WriteString(v)
	}
	if v, found := n.Labels["provisioner.cast.ai/node-configuration-version"]; found {
		_, _ = hash.WriteString(v)
	}
	_, _ = hash.WriteString(n.Status.NodeInfo.Architecture)
	_, _ = hash.WriteString(n.Status.NodeInfo.ContainerRuntimeVersion)
	_, _ = hash.WriteString(n.Status.NodeInfo.KubeletVersion)
	_, _ = hash.WriteString(n.Status.NodeInfo.OSImage)
	return hash.Sum64()
}
