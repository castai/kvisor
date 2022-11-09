package imagescan

import (
	"strings"
	"sync"

	"github.com/samber/lo"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"

	"github.com/castai/sec-agent/controller"
)

type image struct {
	id               string
	name             string
	containerRuntime string
	podIDs           map[string]struct{}
	resourcesIDs     map[string]struct{}
	nodeNames        map[string]struct{}
	podTolerations   []corev1.Toleration

	scanned          bool
	resourcesChanged bool
	failures         int
}

func newDeltaState(scannedImageIDs []string) *deltaState {
	images := map[string]*image{}
	for _, imgID := range scannedImageIDs {
		images[imgID] = &image{
			id:      imgID,
			scanned: true,
		}
	}
	return &deltaState{
		images: map[string]*image{},
		rs:     make(map[string]*appsv1.ReplicaSet),
		jobs:   make(map[string]*batchv1.Job),
	}
}

type deltaState struct {
	images map[string]*image
	rs     map[string]*appsv1.ReplicaSet
	jobs   map[string]*batchv1.Job
	mu     sync.RWMutex
}

func (d *deltaState) upsert(o controller.Object) {
	d.mu.Lock()
	defer d.mu.Unlock()

	key := controller.ObjectKey(o)
	switch t := o.(type) {
	case *corev1.Pod:
		if t.Status.Phase == corev1.PodRunning {
			d.upsertImages(t)
		}
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
	switch t := o.(type) {
	case *corev1.Pod:
		d.deleteImages(t)
	case *batchv1.Job:
		delete(d.jobs, key)
	case *appsv1.ReplicaSet:
		delete(d.rs, key)
	}
}

func (d *deltaState) upsertImages(pod *corev1.Pod) {
	containers := pod.Spec.Containers
	containers = append(containers, pod.Spec.InitContainers...)

	containerStatuses := pod.Status.ContainerStatuses
	containerStatuses = append(containerStatuses, pod.Status.InitContainerStatuses...)

	for _, cont := range containers {
		cs, found := lo.Find(containerStatuses, func(v corev1.ContainerStatus) bool {
			return v.Name == cont.Name
		})
		if !found {
			continue
		}

		key := cs.ImageID
		nodeName := pod.Spec.NodeName
		resourceID := getPodOwnerID(pod, d.rs, d.jobs)
		v, found := d.images[key]
		if found {
			v.nodeNames[nodeName] = struct{}{}
			v.podIDs[string(pod.UID)] = struct{}{}
			if _, found := v.resourcesIDs[resourceID]; !found {
				v.resourcesChanged = true
				v.resourcesIDs[resourceID] = struct{}{}
			}
		} else {
			d.images[key] = &image{
				name:             cont.Image,
				id:               cs.ImageID,
				containerRuntime: getContainerRuntime(cs.ContainerID),
				podIDs: map[string]struct{}{
					string(pod.UID): {},
				},
				resourcesIDs: map[string]struct{}{
					resourceID: {},
				},
				nodeNames: map[string]struct{}{
					nodeName: {},
				},
				podTolerations: pod.Spec.Tolerations,
			}
		}
	}
}

func (d *deltaState) deleteImages(pod *corev1.Pod) {
	for key, img := range d.images {
		podID := string(pod.UID)
		delete(img.podIDs, podID)
		if len(img.podIDs) == 0 {
			delete(d.images, key)
		}
	}
}

func (d *deltaState) getImages() map[string]*image {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return d.images
}

func (d *deltaState) updateImage(img *image) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.images[img.id] = img
}

func getContainerRuntime(containerID string) string {
	parts := strings.Split(containerID, "://")
	if len(parts) != 2 {
		return ""
	}
	return parts[0]
}

func getPodOwnerID(pod *corev1.Pod, rsMap map[string]*appsv1.ReplicaSet, jobsMap map[string]*batchv1.Job) string {
	if len(pod.OwnerReferences) == 0 {
		return string(pod.UID)
	}

	ref := pod.OwnerReferences[0]

	switch ref.Kind {
	case "ReplicaSet":
		for _, val := range rsMap {
			if val.UID == ref.UID {
				if len(val.OwnerReferences) > 0 {
					return string(val.OwnerReferences[0].UID)
				}
				return string(ref.UID)
			}
		}
	case "Job":
		for _, val := range jobsMap {
			if val.UID == ref.UID {
				if len(val.OwnerReferences) > 0 {
					return string(val.OwnerReferences[0].UID)
				}
				return string(ref.UID)
			}
		}
	}

	return string(ref.UID)
}
