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
		objectMap: make(map[string]*NodeJob),
		mu:        sync.Mutex{},
	}
}

type NodeJob struct {
	node *corev1.Node

	backoff wait.Backoff
	next    time.Time
}

func (n *NodeJob) ready() bool {
	if n.next.Before(time.Now()) {
		return true
	}
	return false
}

func (n *NodeJob) failed() {
	n.next = time.Now().Add(n.backoff.Step())
}

type nodeDeltaState struct {
	objectMap map[string]*NodeJob
	mu        sync.Mutex
}

func (d *nodeDeltaState) upsert(o *corev1.Node) {
	d.mu.Lock()
	defer d.mu.Unlock()

	nodeBackoff := wait.Backoff{
		Duration: time.Second * 15,
		Factor:   2,
		Steps:    3,
	}

	w := &NodeJob{
		backoff: nodeBackoff,
		node:    o,
		next:    time.Now(),
	}

	key := controller.ObjectKey(o)
	d.objectMap[key] = w
}

func (d *nodeDeltaState) delete(o *corev1.Node) {
	d.mu.Lock()
	defer d.mu.Unlock()

	delete(d.objectMap, controller.ObjectKey(o))
}

func (d *nodeDeltaState) peek() []*NodeJob {
	d.mu.Lock()
	defer d.mu.Unlock()

	return lo.Values(d.objectMap)
}
