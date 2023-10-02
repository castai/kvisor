package kubebench

import (
	"sync"
	"time"

	"github.com/samber/lo"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/castai/kvisor/kube"
)

func newDeltaState() *nodeDeltaState {
	return &nodeDeltaState{
		objectMap: make(map[string]*nodeJob),
		mu:        sync.Mutex{},
	}
}

type nodeJob struct {
	node *corev1.Node

	backoff wait.Backoff
	next    time.Time
}

func (n *nodeJob) ready() bool {
	return n.next.Before(time.Now())
}

func (n *nodeJob) setFailed() {
	n.next = time.Now().Add(n.backoff.Step())
}

type nodeDeltaState struct {
	objectMap map[string]*nodeJob
	mu        sync.Mutex
}

func (d *nodeDeltaState) upsert(o *corev1.Node) {
	d.mu.Lock()
	defer d.mu.Unlock()

	key := kube.ObjectKey(o)
	if job, ok := d.objectMap[key]; ok {
		job.node = o
		return
	}

	nodeBackoff := wait.Backoff{
		Duration: time.Second * 15,
		Factor:   3,
		Steps:    8,
	}
	w := &nodeJob{
		backoff: nodeBackoff,
		node:    o,
		next:    time.Now(),
	}
	d.objectMap[key] = w
}

func (d *nodeDeltaState) delete(o *corev1.Node) {
	d.mu.Lock()
	defer d.mu.Unlock()

	delete(d.objectMap, kube.ObjectKey(o))
}

func (d *nodeDeltaState) peek() []*nodeJob {
	d.mu.Lock()
	defer d.mu.Unlock()

	return lo.Values(d.objectMap)
}
