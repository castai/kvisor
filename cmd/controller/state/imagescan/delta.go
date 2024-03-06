package imagescan

import (
	"strings"
	"sync"
	"time"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	imagescanconfig "github.com/castai/kvisor/cmd/agent/imagescan/config"

	"github.com/castai/kvisor/cmd/controller/kube"
	"github.com/samber/lo"
	"gopkg.in/inf.v0"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
)

const defaultImageOs = "linux"
const defaultImageArch = "amd64"

type kubeClient interface {
	GetOwnerUID(obj kube.Object) string
	GetKvisorAgentImageDetails() (kube.ImageDetails, bool)
}

func newImage() *image {
	return &image{
		owners:  map[string]*imageOwner{},
		scanned: false,
		retryBackoff: wait.Backoff{
			Duration: time.Second * 60,
			Factor:   3,
			Steps:    8,
		},
	}
}

func newDeltaState(kubeClient kubeClient) *deltaState {
	return &deltaState{
		kubeClient: kubeClient,
		images:     map[string]*image{},
		nodes:      map[string]*corev1.Node{},
	}
}

type deltaState struct {
	kubeClient kubeClient

	mu sync.Mutex

	// images holds current cluster images state. image struct contains associated nodes and owners.
	images map[string]*image
	nodes  map[string]*corev1.Node
}

func (d *deltaState) Upsert(o kube.Object) {
	d.mu.Lock()
	defer d.mu.Unlock()

	switch v := o.(type) {
	case *corev1.Pod:
		d.handlePodUpdate(v)
	case *corev1.Node:
		d.nodes[v.Name] = v
	}
}

func (d *deltaState) Delete(o kube.Object) {
	d.mu.Lock()
	defer d.mu.Unlock()

	switch v := o.(type) {
	case *corev1.Pod:
		d.handlePodDelete(v)
	case *corev1.Node:
		delete(d.nodes, v.Name)
	}
}

func (d *deltaState) GetImagesCopy() []*image {
	d.mu.Lock()
	defer d.mu.Unlock()

	res := make([]*image, 0, len(d.images))
	for _, img := range d.images {
		imgCopy := *img
		res = append(res, &imgCopy)
	}
	return res
}

func (d *deltaState) SetImageScanError(imgKey string, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	img := d.images[imgKey]
	if img == nil {
		return
	}

	img.failures++
	img.lastScanErr = err

	img.nextScan = time.Now().UTC().Add(img.retryBackoff.Step())
}

func (d *deltaState) SetResourcesUpdatedAt(images []*image, now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, img := range images {
		if deltaImg, ok := d.images[img.key]; ok {
			deltaImg.resourcesUpdatedAt = now
		}
	}
}

func (d *deltaState) SetImageScanned(imgKey string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if img, ok := d.images[imgKey]; ok {
		img.scanned = true
	}
}

func (d *deltaState) UpdateRemoteSyncedAt(images []*image, now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, img := range images {
		if deltaImg, ok := d.images[img.key]; ok {
			deltaImg.lastRemoteSyncAt = now
		}
	}
}

func (d *deltaState) SetScannedImages(images []*castaipb.Image) {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, remoteImage := range images {
		if remoteImage.ScanStatus == castaipb.ImageScanStatus_IMAGE_SCAN_STATUS_SCANNED {
			d.setImageScanned(remoteImage)
		}
	}
}

func (d *deltaState) setImageScanned(scannedImg *castaipb.Image) {
	for _, img := range d.images {
		if img.id == scannedImg.Id && img.architecture == scannedImg.Architecture {
			img.scanned = true
		}
	}
}

func (d *deltaState) handlePodUpdate(v *corev1.Pod) {
	if v.Status.Phase == corev1.PodSucceeded {
		d.handlePodDelete(v)
	}
	if v.Status.Phase == corev1.PodRunning {
		d.upsertImages(v)
	}
}

func (d *deltaState) upsertImages(pod *corev1.Pod) {
	now := time.Now().UTC()

	containers := pod.Spec.Containers
	containers = append(containers, pod.Spec.InitContainers...)
	containerStatuses := pod.Status.ContainerStatuses
	containerStatuses = append(containerStatuses, pod.Status.InitContainerStatuses...)
	podID := string(pod.UID)
	// Get the resource id of Deployment, ReplicaSet, StatefulSet, Job, CronJob.
	ownerResourceID := d.kubeClient.GetOwnerUID(pod)

	for _, cont := range containers {
		cs, found := lo.Find(containerStatuses, func(v corev1.ContainerStatus) bool {
			return v.Name == cont.Name
		})
		if !found {
			continue
		}
		if cs.ImageID == "" {
			continue
		}
		if cont.Image == "" {
			continue
		}

		platform := d.getPodPlatform(pod)
		key := cs.ImageID + platform.architecture + cont.Image
		img, found := d.images[key]
		if !found {
			img = newImage()
			img.name = cont.Image
			img.key = key
			img.architecture = platform.architecture
			img.os = platform.os
		}
		img.id = cs.ImageID
		img.containerRuntime = getContainerRuntime(cs.ContainerID)

		// Upsert image owners.
		if owner, found := img.owners[ownerResourceID]; found {
			owner.podIDs[podID] = struct{}{}
		} else {
			img.owners[ownerResourceID] = &imageOwner{
				podIDs: map[string]struct{}{
					podID: {},
				},
			}
			img.ownerChangedAt = now
		}

		d.images[key] = img
	}
}

func (d *deltaState) handlePodDelete(pod *corev1.Pod) {
	now := time.Now().UTC()
	for imgKey, img := range d.images {
		if img.architecture != d.getPodPlatform(pod).architecture {
			continue
		}

		podID := string(pod.UID)

		ownerResourceID := d.kubeClient.GetOwnerUID(pod)
		if owner, found := img.owners[ownerResourceID]; found {
			delete(owner.podIDs, podID)
			if len(owner.podIDs) == 0 {
				delete(img.owners, ownerResourceID)
				img.ownerChangedAt = now
			}
		}

		if len(img.owners) == 0 {
			delete(d.images, imgKey)
		}
	}
}

type platform struct {
	architecture string
	os           string
}

func (d *deltaState) getPodPlatform(pod *corev1.Pod) platform {
	n, ok := d.nodes[pod.Spec.NodeName]
	if ok && n.Status.NodeInfo.Architecture != "" && n.Status.NodeInfo.OperatingSystem != "" {
		return platform{
			architecture: n.Status.NodeInfo.Architecture,
			os:           n.Status.NodeInfo.OperatingSystem,
		}
	}
	return platform{
		architecture: defaultImageArch,
		os:           defaultImageOs,
	}
}

func getContainerRuntime(containerID string) imagescanconfig.Runtime {
	parts := strings.Split(containerID, "://")
	if len(parts) != 2 {
		return ""
	}
	cr := parts[0]
	switch cr {
	case "docker":
		return imagescanconfig.RuntimeDocker
	case "containerd":
		return imagescanconfig.RuntimeContainerd
	}
	return ""
}

type pod struct {
	id            types.UID
	requestCPU    *inf.Dec
	requestMemory *inf.Dec
}

type imageOwner struct {
	podIDs map[string]struct{}
}

type image struct {
	key string // used in map[string]*image

	// id is ImageID from container status. It includes image name and digest.
	//
	// Note: ImageID's digest part could confuse you with actual image digest.
	// Kubernetes calculates digest based on one of these cases:
	// 1. Index manifest (if exists).
	// 2. Manifest file.
	// 3. Config file. Mostly legacy for old images without manifest.
	id string

	// name is image name from container spec.
	//
	// Note: We select image name from container spec (not from container status).
	// In container status you will see fully qualified image name, eg. docker.io/grafana/grafana:latest
	// while on container spec you will see user defined image name which may not be fully qualified, eg: grafana/grafana:latest
	name string

	architecture     string
	os               string
	containerRuntime imagescanconfig.Runtime

	// owners map key points to higher level k8s resource for that image. (Image Affected resource in CAST AI console).
	// Example: In most cases Pod will be managed by deployment, so owner id will point to Deployment's uuid.
	owners map[string]*imageOwner

	scanned      bool
	lastScanErr  error
	failures     int          // Used for sorting. We want to scan non-failed images first.
	retryBackoff wait.Backoff // Retry state for failed images.
	nextScan     time.Time    // Set based on retry backoff.

	lastRemoteSyncAt   time.Time // Time then image state was synced from remote.
	ownerChangedAt     time.Time // Time when new image owner was added
	resourcesUpdatedAt time.Time // Time when image was synced with backend
}

func (img *image) isUnused() bool {
	return len(img.owners) == 0
}
