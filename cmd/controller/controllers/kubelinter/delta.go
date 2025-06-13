package kubelinter

import (
	"sync"

	"github.com/castai/kvisor/cmd/controller/kube"
	"github.com/samber/lo"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

func newDeltaState() *deltaState {
	return &deltaState{
		objectMap: make(map[types.UID]kube.Object),
		mu:        sync.Mutex{},
	}
}

type deltaState struct {
	objectMap map[types.UID]kube.Object
	mu        sync.Mutex
}

func (d *deltaState) insert(objs ...kube.Object) {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, o := range objs {
		key := o.GetUID()
		if _, ok := d.objectMap[key]; !ok {
			d.objectMap[key] = o
		}
	}
}

func (d *deltaState) upsert(o kube.Object) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Skip linting pod updates.
	switch o.(type) {
	case *v1.Pod:
		return
	}

	key := o.GetUID()
	d.objectMap[key] = o
}

func (d *deltaState) delete(o kube.Object) {
	d.mu.Lock()
	defer d.mu.Unlock()

	delete(d.objectMap, o.GetUID())
}

func (d *deltaState) flush() []kube.Object {
	d.mu.Lock()
	defer d.mu.Unlock()
	defer func() {
		d.objectMap = make(map[types.UID]kube.Object)
	}()

	return lo.Values(d.objectMap)
}
