package kubelinter

import (
	"sync"

	"k8s.io/apimachinery/pkg/types"

	"github.com/castai/sec-agent/controller"
)

func newDeltaState() *deltaState {
	return &deltaState{
		objectMap: make(map[types.UID]controller.Object),
		mu:        sync.Mutex{},
	}
}

type deltaState struct {
	objectMap map[types.UID]controller.Object
	mu        sync.Mutex
}

func (d *deltaState) insert(objs ...controller.Object) {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, o := range objs {
		key := o.GetUID()
		if _, ok := d.objectMap[key]; !ok {
			d.objectMap[key] = o
		}
	}
}

func (d *deltaState) upsert(o controller.Object) {
	d.mu.Lock()
	defer d.mu.Unlock()

	key := o.GetUID()
	d.objectMap[key] = o
}

func (d *deltaState) delete(o controller.Object) {
	d.mu.Lock()
	defer d.mu.Unlock()

	delete(d.objectMap, o.GetUID())
}

func (d *deltaState) flush() []controller.Object {
	d.mu.Lock()
	defer d.mu.Unlock()
	defer func() {
		d.objectMap = make(map[types.UID]controller.Object)
	}()

	res := make([]controller.Object, 0, len(d.objectMap))
	for _, o := range d.objectMap {
		res = append(res, o)
	}

	return res
}
