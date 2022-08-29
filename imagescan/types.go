package imagescan

import (
	"sync"

	corev1 "k8s.io/api/core/v1"

	"github.com/castai/sec-agent/controller"
)

func newDeltaState() *deltaState {
	return &deltaState{
		pods: make(map[string]*corev1.Pod),
		mu:   sync.Mutex{},
	}
}

type deltaState struct {
	pods map[string]*corev1.Pod
	mu   sync.Mutex
}

func (d *deltaState) upsert(o controller.Object) {
	d.mu.Lock()
	defer d.mu.Unlock()

	key := controller.ObjectKey(o)
	switch t := o.(type) {
	case *corev1.Pod:
		d.pods[key] = t
	}
}

func (d *deltaState) delete(o controller.Object) {
	d.mu.Lock()
	defer d.mu.Unlock()

	key := controller.ObjectKey(o)
	switch t := o.(type) {
	case *corev1.Pod:
		d.pods[key] = t
		delete(d.pods, controller.ObjectKey(o))
	}
}

func (d *deltaState) getPods() map[string]*corev1.Pod {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.pods
}

func (d *deltaState) deletePods() {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.pods = make(map[string]*corev1.Pod)
}
