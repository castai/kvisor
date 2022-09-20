package kubebench

import (
	corev1 "k8s.io/api/core/v1"
	"sync"

	"github.com/castai/sec-agent/controller"
)

func newDeltaState() *nodeDeltaState {
	return &nodeDeltaState{
		objectMap: make(map[string]corev1.Node),
		mu:        sync.Mutex{},
	}
}

type nodeDeltaState struct {
	objectMap map[string]corev1.Node
	mu        sync.Mutex
}

func (d *nodeDeltaState) upsert(o *corev1.Node) {
	d.mu.Lock()
	defer d.mu.Unlock()

	key := controller.ObjectKey(o)
	d.objectMap[key] = *o
}

func (d *nodeDeltaState) delete(o *corev1.Node) {
	d.mu.Lock()
	defer d.mu.Unlock()

	delete(d.objectMap, controller.ObjectKey(o))
}

func (d *nodeDeltaState) peek() []corev1.Node {
	d.mu.Lock()
	defer d.mu.Unlock()

	res := make([]corev1.Node, 0, len(d.objectMap))
	for _, o := range d.objectMap {
		res = append(res, o)
	}

	return res
}
