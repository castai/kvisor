package kubebench

import (
	"sync"
	"time"

	"github.com/samber/lo"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/castai/sec-agent/controller"
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
	// Make sure that node is ready.
	if !isNodeReady(o) {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	key := controller.ObjectKey(o)
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

	delete(d.objectMap, controller.ObjectKey(o))
}

func (d *nodeDeltaState) peek() []*nodeJob {
	d.mu.Lock()
	defer d.mu.Unlock()

	return lo.Values(d.objectMap)
}

func isNodeReady(n *corev1.Node) bool {
	if len(n.Status.Conditions) == 0 {
		return false
	}
	lastCondition := n.Status.Conditions[len(n.Status.Conditions)-1]
	return lastCondition.Type == corev1.NodeReady && lastCondition.Status == corev1.ConditionTrue
}
