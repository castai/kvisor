package kubebench

import (
	"sync"

	"github.com/castai/sec-agent/controller"
)

const (
	castNodeConfigKey = "provisioner.cast.ai/node-configuration-id"
	gkeNodepoolKey    = "cloud.google.com/gke-nodepool"
)

func newDeltaState() *nodeDeltaState {
	return &nodeDeltaState{
		objectMap: make(map[string]controller.Object),
		mu:        sync.Mutex{},
	}
}

type nodeDeltaState struct {
	objectMap map[string]controller.Object
	mu        sync.Mutex
}

func (d *nodeDeltaState) upsert(o controller.Object) {
	d.mu.Lock()
	defer d.mu.Unlock()

	key := controller.ObjectKey(o)
	d.objectMap[key] = o
}

func (d *nodeDeltaState) delete(o controller.Object) {
	d.mu.Lock()
	defer d.mu.Unlock()

	delete(d.objectMap, controller.ObjectKey(o))
}

func (d *nodeDeltaState) flush() []controller.Object {
	d.mu.Lock()
	defer d.mu.Unlock()
	defer func() {
		d.objectMap = make(map[string]controller.Object)
	}()

	res := make([]controller.Object, 0, len(d.objectMap))
	for _, o := range d.objectMap {
		res = append(res, o)
	}

	return res
}
