package imagescan

import (
	"sync"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"

	"github.com/castai/sec-agent/controller"
)

func newDeltaState() *deltaState {
	return &deltaState{
		pods: make(map[string]*corev1.Pod),
		rs:   make(map[string]*appsv1.ReplicaSet),
		jobs: make(map[string]*batchv1.Job),
	}
}

type deltaState struct {
	pods map[string]*corev1.Pod
	rs   map[string]*appsv1.ReplicaSet
	jobs map[string]*batchv1.Job
	mu   sync.RWMutex
}

func (d *deltaState) upsert(o controller.Object) {
	d.mu.Lock()
	defer d.mu.Unlock()

	key := controller.ObjectKey(o)
	switch t := o.(type) {
	case *corev1.Pod:
		d.pods[key] = t
	case *batchv1.Job:
		d.jobs[key] = t
	case *appsv1.ReplicaSet:
		d.rs[key] = t
	}
}

func (d *deltaState) delete(o controller.Object) {
	d.mu.Lock()
	defer d.mu.Unlock()

	key := controller.ObjectKey(o)
	switch o.(type) {
	case *corev1.Pod:
		delete(d.pods, key)
	case *batchv1.Job:
		delete(d.jobs, key)
	case *appsv1.ReplicaSet:
		delete(d.rs, key)
	}
}

func (d *deltaState) getPods() map[string]*corev1.Pod {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return d.pods
}

func (d *deltaState) getReplicaSets() map[string]*appsv1.ReplicaSet {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return d.rs
}

func (d *deltaState) getJobs() map[string]*batchv1.Job {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return d.jobs
}

func (d *deltaState) deletePods(podsMap map[string]*corev1.Pod) {
	d.mu.Lock()
	defer d.mu.Unlock()

	for key := range podsMap {
		delete(d.pods, key)
	}
}
