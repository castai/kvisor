package kubelinter

import (
	"sync"

	"github.com/castai/sec-agent/controller"
)

func newDeltaState() *deltaState {
	return &deltaState{
		objectMap: make(map[string]controller.Object),
		mu:        sync.Mutex{},
	}
}

type deltaState struct {
	objectMap map[string]controller.Object
	mu        sync.Mutex
}

func (d *deltaState) upsert(o controller.Object) {
	d.mu.Lock()
	defer d.mu.Unlock()

	key := controller.ObjectKey(o)
	d.objectMap[key] = o
}

func (d *deltaState) delete(o controller.Object) {
	d.mu.Lock()
	defer d.mu.Unlock()

	delete(d.objectMap, controller.ObjectKey(o))
}

func (d *deltaState) flush() []controller.Object {
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
