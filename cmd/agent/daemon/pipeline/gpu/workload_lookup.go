package gpu

import (
	"context"

	kubepb "github.com/castai/kvisor/api/v1/kube"
	lru "github.com/hashicorp/golang-lru/v2"
)

type WorkloadLookup interface {
	FindWorkloadForPod(ctx context.Context, podName, namespace string) (workloadName, workloadKind string, err error)
}

type workloadIdentity struct {
	name string
	kind string
}

type workloadLookup struct {
	client            kubepb.KubeAPIClient
	workloadLabelKeys []string
	cache             *lru.Cache[string, workloadIdentity]
}

func newWorkloadLookup(client kubepb.KubeAPIClient, workloadLabelKeys []string, cacheSize int) (*workloadLookup, error) {
	cache, err := lru.New[string, workloadIdentity](cacheSize)
	if err != nil {
		return nil, err
	}
	return &workloadLookup{
		client:            client,
		workloadLabelKeys: workloadLabelKeys,
		cache:             cache,
	}, nil
}

func (w *workloadLookup) FindWorkloadForPod(ctx context.Context, podName, namespace string) (workloadName, workloadKind string, err error) {
	key := namespace + "/" + podName
	if v, ok := w.cache.Get(key); ok {
		return v.name, v.kind, nil
	}

	resp, err := w.client.GetPodByName(ctx, &kubepb.GetPodByNameRequest{
		Namespace:         namespace,
		Name:              podName,
		WorkloadLabelKeys: w.workloadLabelKeys,
	})
	if err != nil {
		return "", "", err
	}

	wName := resp.Pod.WorkloadName
	wKind := workloadKindToString(resp.Pod.WorkloadKind)
	w.cache.Add(key, workloadIdentity{name: wName, kind: wKind})
	return wName, wKind, nil
}

func workloadKindToString(kind kubepb.WorkloadKind) string {
	switch kind {
	case kubepb.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT:
		return "Deployment"
	case kubepb.WorkloadKind_WORKLOAD_KIND_REPLICA_SET:
		return "ReplicaSet"
	case kubepb.WorkloadKind_WORKLOAD_KIND_DAEMON_SET:
		return "DaemonSet"
	case kubepb.WorkloadKind_WORKLOAD_KIND_STATEFUL_SET:
		return "StatefulSet"
	case kubepb.WorkloadKind_WORKLOAD_KIND_JOB:
		return "Job"
	case kubepb.WorkloadKind_WORKLOAD_KIND_CRONJOB:
		return "CronJob"
	case kubepb.WorkloadKind_WORKLOAD_KIND_ROLLOUT:
		return "Rollout"
	default:
		return "Pod"
	}
}
