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

	"github.com/cenkalti/backoff/v4"
	"github.com/google/uuid"
	lru "github.com/hashicorp/golang-lru"
	jsoniter "github.com/json-iterator/go"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"

	"github.com/castai/kvisor/castai"
	"github.com/castai/kvisor/controller"
	"github.com/castai/kvisor/linters/kubebench/spec"
	"github.com/castai/kvisor/log"
	"github.com/castai/kvisor/metrics"
)

const (
	nodeScanTimeout   = 5 * time.Minute
	labelJobName      = "job-name"
	maxConcurrentJobs = 1
)

func NewSubscriber(
	log logrus.FieldLogger,
	client kubernetes.Interface,
	castaiNamespace string,
	provider string,
	scanInterval time.Duration,
	castClient castai.Client,
	logsReader log.PodLogProvider,
	scannedNodes []string,
) controller.ObjectSubscriber {
	nodeCache, _ := lru.New(1000)
	for _, node := range scannedNodes {
		nodeCache.Add(node, struct{}{})
	}

	return &Subscriber{
		log:                           log,
		client:                        client,
		castaiNamespace:               castaiNamespace,
		delta:                         newDeltaState(),
		provider:                      provider,
		castClient:                    castClient,
		logsProvider:                  logsReader,
		scanInterval:                  scanInterval,
		scannedNodes:                  nodeCache,
		finishedJobDeleteWaitDuration: 10 * time.Second,
		kubeBenchReportsCache:         map[uint64]*castai.KubeBenchReport{},
	}
}

type Subscriber struct {
	log                           logrus.FieldLogger
	client                        kubernetes.Interface
	castaiNamespace               string
	castClient                    castai.Client
	delta                         *nodeDeltaState
	provider                      string
	logsProvider                  log.PodLogProvider
	scanInterval                  time.Duration
	finishedJobDeleteWaitDuration time.Duration
	scannedNodes                  *lru.Cache
	// After job finishes with store report in memory grouped by similar nodes.
	// This allows to reduce number of jobs since we near identical reports.
	kubeBenchReportsCache   map[uint64]*castai.KubeBenchReport
	kubeBenchReportsCacheMu sync.Mutex
}

func (s *Subscriber) OnAdd(obj controller.Object) {
	node, ok := obj.(*corev1.Node)
	if ok {
		_, scanned := s.scannedNodes.Get(string(node.GetUID()))
		if isNodeReady(node) && !scanned {
			s.delta.upsert(node)
		}
	}
}

func (s *Subscriber) OnUpdate(obj controller.Object) {
	s.OnAdd(obj)
}

func (s *Subscriber) OnDelete(obj controller.Object) {
	node, ok := obj.(*corev1.Node)
	if ok {
		s.delta.delete(node)
		s.scannedNodes.Remove(string(obj.GetUID()))
	}
}

func (s *Subscriber) Run(ctx context.Context) error {
	ticker := time.NewTicker(s.scanInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			err := s.process(ctx)
			if err != nil && !errors.Is(err, context.Canceled) {
				s.log.Errorf("error linting nodes: %v", err)
			}
		}
	}
}

func (s *Subscriber) process(ctx context.Context) (rerr error) {
	nodes := s.findNodesForScan()
	if len(nodes) == 0 {
		return nil
	}

	s.log.Infof("processing kube-bench")
	defer s.log.Info("processing kube-bench done")
	var wg sync.WaitGroup
	for _, n := range nodes {
		job := n
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(ctx, nodeScanTimeout)
			defer cancel()
			err := s.lintNode(ctx, job.node)
			if err != nil {
				s.log.WithField("node", job.node.Name).Errorf("kube-bench: %v", err)
				job.setFailed()
				return
			}
			s.delta.delete(job.node)
		}()
	}

	wg.Wait()
	return nil
}

func (s *Subscriber) findNodesForScan() []*nodeJob {
	nodes := s.delta.peek()
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

func (s *Subscriber) RequiredInformers() []reflect.Type {
	return []reflect.Type{reflect.TypeOf(&corev1.Node{})}
}

func (s *Subscriber) lintNode(ctx context.Context, node *corev1.Node) (rerr error) {
	start := time.Now()

	// Check if node is in node group for already scanned jobs.
	// In found we can skip job scheduling.
	if cachedReport, found := s.findScannedReport(node); found {
		defer func() {
			metrics.IncScansTotal(metrics.ScanTypeKubeBenchCached, rerr)
			metrics.ObserveScanDuration(metrics.ScanTypeKubeBenchCached, start)
		}()
		report := &castai.KubeBenchReport{
			OverallControls: cachedReport.OverallControls,
			Node: castai.Node{
				NodeName:   node.Name,
				ResourceID: uuid.MustParse(string(node.UID)),
			},
		}
		err := s.castClient.SendCISReport(ctx, report)
		if err != nil {
			return err
		}

		s.scannedNodes.Add(string(node.UID), struct{}{})
		return nil
	}

	defer func() {
		metrics.IncScansTotal(metrics.ScanTypeKubeBench, rerr)
		metrics.ObserveScanDuration(metrics.ScanTypeKubeBench, start)
	}()

	s.log.Debugf("starting kube-bench lint for node=%s", node.Name)
	jobName := generateName(node.GetName())
	err := s.deleteJob(ctx, jobName)
	if err != nil && !k8serrors.IsNotFound(err) {
		s.log.WithError(err).Errorf("can not delete job %q", jobName)
		return err
	}

	if err == nil {
		err = s.waitJobDeleted(ctx, jobName)
		if err != nil {
			return err
		}
	}

	kubeBenchPod, err := s.createKubebenchJob(ctx, node, jobName)
	if err != nil {
		return err
	}
	report, err := s.getReportFromLogs(ctx, node, kubeBenchPod.Name)
	if err != nil {
		return fmt.Errorf("reading kube-bench report from pod logs: %w", err)
	}
	s.addReportToCache(node, report)
	err = s.castClient.SendCISReport(ctx, report)
	if err != nil {
		return err
	}

	s.scannedNodes.Add(string(node.UID), struct{}{})
	if s.finishedJobDeleteWaitDuration != 0 {
		go func() {
			// Wait some time before deleting job. This is useful for observability and e2e tests.
			select {
			case <-ctx.Done():
				return
			case <-time.After(s.finishedJobDeleteWaitDuration):
			}
			err = s.deleteJob(ctx, jobName)
			if err != nil {
				s.log.Errorf("failed deleting job %s: %v", jobName, err)
			}
		}()
	} else {
		err = s.deleteJob(ctx, jobName)
		if err != nil {
			s.log.Errorf("failed deleting job %s: %v", jobName, err)
		}
	}

	return nil
}

func (s *Subscriber) findScannedReport(n *corev1.Node) (*castai.KubeBenchReport, bool) {
	s.kubeBenchReportsCacheMu.Lock()
	defer s.kubeBenchReportsCacheMu.Unlock()

	key := getNodeGroupKey(n)
	report, found := s.kubeBenchReportsCache[key]
	return report, found
}

func (s *Subscriber) addReportToCache(n *corev1.Node, report *castai.KubeBenchReport) {
	s.kubeBenchReportsCacheMu.Lock()
	defer s.kubeBenchReportsCacheMu.Unlock()

	key := getNodeGroupKey(n)
	s.kubeBenchReportsCache[key] = report
}

// We are interested in kube-bench pod succeeding and not the Job
func (s *Subscriber) createKubebenchJob(ctx context.Context, node *corev1.Node, jobName string) (*corev1.Pod, error) {
	specFn := resolveSpec(s.provider, node)

	job, err := s.client.BatchV1().
		Jobs(s.castaiNamespace).
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
			pods, err := s.client.CoreV1().Pods(s.castaiNamespace).List(ctx, metav1.ListOptions{
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
	return s.client.BatchV1().Jobs(s.castaiNamespace).Delete(ctx, jobName, metav1.DeleteOptions{
		GracePeriodSeconds: lo.ToPtr(int64(0)),
		PropagationPolicy:  lo.ToPtr(metav1.DeletePropagationBackground),
	})
}

func (s *Subscriber) waitJobDeleted(ctx context.Context, jobName string) error {
	deleteCtx, cancel := context.WithTimeout(ctx, 1*time.Minute)
	defer cancel()
	return backoff.Retry(
		func() error {
			_, err := s.client.BatchV1().Jobs(s.castaiNamespace).Get(deleteCtx, jobName, metav1.GetOptions{})
			if err != nil {
				if k8serrors.IsNotFound(err) {
					return nil
				}

				return backoff.Permanent(err)
			}

			return fmt.Errorf("job not yet deleted")
		}, backoff.WithContext(backoff.NewConstantBackOff(10*time.Second), deleteCtx))
}

func (s *Subscriber) getReportFromLogs(ctx context.Context, node *corev1.Node, kubeBenchPodName string) (*castai.KubeBenchReport, error) {
	logReader, err := s.logsProvider.GetLogReader(ctx, s.castaiNamespace, kubeBenchPodName)
	if err != nil {
		return nil, err
	}
	defer logReader.Close()

	report, err := io.ReadAll(logReader)
	if err != nil {
		return nil, err
	}

	var customReport castai.KubeBenchReport
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
		return nil, fmt.Errorf("can't parse node UID: %w", err)
	}

	customReport.Node = castai.Node{
		NodeName:   node.Name,
		ResourceID: nodeID,
	}

	return &customReport, nil
}

func generateName(nodeName string) string {
	h := fnv.New32a()
	h.Write([]byte(nodeName))
	return fmt.Sprintf("kube-bench-%d", h.Sum32())
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
