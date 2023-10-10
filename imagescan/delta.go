package imagescan

import (
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/castai/kvisor/castai"
	"github.com/samber/lo"
	"gopkg.in/inf.v0"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"

	imgcollectorconfig "github.com/castai/kvisor/cmd/imgcollector/config"
	"github.com/castai/kvisor/kube"
)

var (
	errNoCandidates = errors.New("no candidates")
)

const defaultImageArch = "amd64"

type podOwnerGetter interface {
	GetPodOwnerID(pod *corev1.Pod) string
}

func newImage(key, imageID, architecture string) *image {
	return &image{
		key:          key,
		id:           imageID,
		architecture: architecture,
		owners:       map[string]*imageOwner{},
		nodes:        map[string]*imageNode{},
		scanned:      false,
		ownerChanges: ownerChanges{},
		retryBackoff: wait.Backoff{
			Duration: time.Second * 60,
			Factor:   3,
			Steps:    8,
		},
	}
}

func newDeltaState(podOwnerGetter podOwnerGetter) *deltaState {
	return &deltaState{
		podOwnerGetter: podOwnerGetter,
		queue:          make(chan deltaQueueItem, 1000),
		images:         map[string]*image{},
		nodes:          make(map[string]*node),
	}
}

type deltaQueueItem struct {
	event kube.Event
	obj   kube.Object
}

type deltaState struct {
	podOwnerGetter podOwnerGetter

	// queue is informers received k8s objects but not yet applied to delta.
	// This allows to have lock free access to delta state during image scan.
	queue chan deltaQueueItem

	// images holds current cluster images state. image struct contains associated nodes and owners.
	images map[string]*image

	nodes map[string]*node

	// If we fail to scan in hostfs mode it will be disabled for all feature image scans.
	hostFSDisabled bool
}

func (d *deltaState) upsert(o kube.Object) {
	switch v := o.(type) {
	case *corev1.Pod:
		d.handlePodUpdate(v)
	case *corev1.Node:
		d.updateNodeUsage(v)
	}
}

func (d *deltaState) delete(o kube.Object) {
	switch v := o.(type) {
	case *corev1.Pod:
		d.handlePodDelete(v)
	case *corev1.Node:
		d.handleNodeDelete(v)
	}
}

func (d *deltaState) handlePodUpdate(v *corev1.Pod) {
	d.upsertImages(v)
	d.updateNodesUsageFromPod(v)
}

func (d *deltaState) updateNodeUsage(v *corev1.Node) {
	n, ok := d.nodes[v.GetName()]
	if !ok {
		n = &node{
			name:           v.GetName(),
			architecture:   v.Status.NodeInfo.Architecture,
			allocatableMem: &inf.Dec{},
			allocatableCPU: &inf.Dec{},
			pods:           make(map[types.UID]*pod),
		}
		d.nodes[v.GetName()] = n
	}
	n.allocatableMem = v.Status.Allocatable.Memory().AsDec()
	n.allocatableCPU = v.Status.Allocatable.Cpu().AsDec()
}

func (d *deltaState) updateNodesUsageFromPod(v *corev1.Pod) {
	switch v.Status.Phase { //nolint:exhaustive
	case corev1.PodRunning, corev1.PodPending:
		n, found := d.nodes[v.Spec.NodeName]
		if !found {
			return
		}

		p, found := n.pods[v.GetUID()]
		if !found {
			p = &pod{
				id:            v.GetUID(),
				requestCPU:    &inf.Dec{},
				requestMemory: &inf.Dec{},
			}
			n.pods[v.GetUID()] = p
		}

		p.requestMemory = sumPodRequestMemory(&v.Spec)
		p.requestCPU = sumPodRequestCPU(&v.Spec)
	default:
		if n, found := d.nodes[v.Spec.NodeName]; found {
			delete(n.pods, v.UID)
		}
	}
}

func (d *deltaState) upsertImages(pod *corev1.Pod) {
	// Skip pods which are not running. If pod is running this means that container image should be already downloaded.
	if pod.Status.Phase != corev1.PodRunning {
		return
	}

	containers := pod.Spec.Containers
	containers = append(containers, pod.Spec.InitContainers...)
	containerStatuses := pod.Status.ContainerStatuses
	containerStatuses = append(containerStatuses, pod.Status.InitContainerStatuses...)
	podID := string(pod.UID)
	// Get the resource id of Deployment, ReplicaSet, StatefulSet, Job, CronJob.
	ownerResourceID := d.podOwnerGetter.GetPodOwnerID(pod)

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

		nodeName := pod.Spec.NodeName
		arch := d.getPodArch(pod)
		key := d.getImageKey(cs.ImageID, arch)
		img, found := d.images[key]
		if !found {
			img = newImage(key, cs.ImageID, arch)
		}
		img.id = cs.ImageID
		img.name = cont.Image
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
			// Add changed owner.
			if img.scanned {
				img.ownerChanges.addedIDS = append(img.ownerChanges.addedIDS, ownerResourceID)
			}
		}

		// Upsert image nodes.
		if imgNode, found := img.nodes[nodeName]; found {
			imgNode.podIDs[podID] = struct{}{}
		} else {
			img.nodes[nodeName] = &imageNode{
				podIDs: map[string]struct{}{
					podID: {},
				},
			}
		}
		d.images[key] = img
	}
}

func (d *deltaState) handlePodDelete(pod *corev1.Pod) {
	for imgKey, img := range d.images {
		if img.architecture != d.getPodArch(pod) {
			continue
		}

		podID := string(pod.UID)
		if n, found := img.nodes[pod.Spec.NodeName]; found {
			delete(n.podIDs, podID)
		}

		ownerResourceID := d.podOwnerGetter.GetPodOwnerID(pod)
		if owner, found := img.owners[ownerResourceID]; found {
			delete(owner.podIDs, podID)
			if len(owner.podIDs) == 0 {
				delete(img.owners, ownerResourceID)
			}
		}

		if len(img.nodes) == 0 && len(img.owners) == 0 {
			delete(d.images, imgKey)
		}
	}

	n, ok := d.nodes[pod.Spec.NodeName]
	if ok {
		delete(n.pods, pod.UID)
	}
}

func (d *deltaState) handleNodeDelete(node *corev1.Node) {
	delete(d.nodes, node.GetName())

	for imgKey, img := range d.images {
		delete(img.nodes, node.Name)

		if img.isUnused() {
			delete(d.images, imgKey)
		}
	}
}

func (d *deltaState) getImages() []*image {
	return lo.Values(d.images)
}

func (d *deltaState) updateImage(i *image, change func(img *image)) {
	img := d.images[i.cacheKey()]
	if img != nil {
		change(img)
	}
}

func (d *deltaState) setImageScanError(i *image, err error) {
	img := d.images[i.cacheKey()]
	if img == nil {
		return
	}

	img.failures++
	img.lastScanErr = err
	if strings.Contains(err.Error(), "no such file or directory") || strings.Contains(err.Error(), "failed to get the layer") {
		img.lastScanErr = errImageScanLayerNotFound
		d.hostFSDisabled = true
	} else if strings.Contains(err.Error(), "UNAUTHORIZED") || strings.Contains(err.Error(), "MANIFEST_UNKNOWN") || strings.Contains(err.Error(), "DENIED") {
		// Error codes from https://github.com/google/go-containerregistry/blob/190ad0e4d556f199a07951d55124f8a394ebccd9/pkg/v1/remote/transport/error.go#L115
		img.lastScanErr = errPrivateImage
	}

	img.nextScan = time.Now().UTC().Add(img.retryBackoff.Step())
}

func (d *deltaState) findBestNode(nodeNames []string, requiredMemory *inf.Dec, requiredCPU *inf.Dec) (string, error) {
	if len(d.nodes) == 0 {
		return "", errNoCandidates
	}

	var candidates []*node
	for _, nodeName := range nodeNames {
		if n, found := d.nodes[nodeName]; found && n.availableMemory().Cmp(requiredMemory) >= 0 && n.availableCPU().Cmp(requiredCPU) >= 0 {
			candidates = append(candidates, n)
		}
	}

	if len(candidates) == 0 {
		return "", errNoCandidates
	}

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].availableCPU().Cmp(candidates[j].allocatableCPU) > 0
	})

	return candidates[0].name, nil
}

func (d *deltaState) nodeCount() int {
	return len(d.nodes)
}

func (d *deltaState) isHostFsDisabled() bool {
	return d.hostFSDisabled
}

func (d *deltaState) setImageScanned(scannedImg castai.ScannedImage) {
	for _, img := range d.images {
		if img.id == scannedImg.ID && img.architecture == scannedImg.Architecture {
			img.scanned = true
		}
	}
}

func (d *deltaState) getImageKey(imageID, arch string) string {
	key := imageID + arch
	return key
}

func (d *deltaState) getPodArch(pod *corev1.Pod) string {
	n, ok := d.nodes[pod.Spec.NodeName]
	if ok && n.architecture != "" {
		return n.architecture
	}
	return defaultImageArch
}

func getContainerRuntime(containerID string) imgcollectorconfig.Runtime {
	parts := strings.Split(containerID, "://")
	if len(parts) != 2 {
		return ""
	}
	cr := parts[0]
	switch cr {
	case "docker":
		return imgcollectorconfig.RuntimeDocker
	case "containerd":
		return imgcollectorconfig.RuntimeContainerd
	}
	return ""
}

type pod struct {
	id            types.UID
	requestCPU    *inf.Dec
	requestMemory *inf.Dec
}

type node struct {
	name           string
	architecture   string
	allocatableMem *inf.Dec
	allocatableCPU *inf.Dec
	pods           map[types.UID]*pod
}

func (n *node) availableMemory() *inf.Dec {
	var result inf.Dec
	result.Add(&result, n.allocatableMem)

	for _, p := range n.pods {
		result.Sub(&result, p.requestMemory)
	}

	return &result
}

func (n *node) availableCPU() *inf.Dec {
	var result inf.Dec
	result.Add(&result, n.allocatableCPU)

	for _, p := range n.pods {
		result.Sub(&result, p.requestCPU)
	}

	return &result
}

func sumPodRequestMemory(spec *corev1.PodSpec) *inf.Dec {
	var result inf.Dec
	for _, container := range spec.Containers {
		result.Add(&result, container.Resources.Requests.Memory().AsDec())
	}

	return &result
}

func sumPodRequestCPU(spec *corev1.PodSpec) *inf.Dec {
	var result inf.Dec
	for _, container := range spec.Containers {
		result.Add(&result, container.Resources.Requests.Cpu().AsDec())
	}

	return &result
}

type imageNode struct {
	podIDs map[string]struct{}
}

type imageOwner struct {
	podIDs map[string]struct{}
}

var (
	errImageScanLayerNotFound = errors.New("image layer not found")
	errPrivateImage           = errors.New("private image")
)

type image struct {
	key string

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
	containerRuntime imgcollectorconfig.Runtime

	// owners map key points to higher level k8s resource for that image. (Image Affected resource in CAST AI console).
	// Example: In most cases Pod will be managed by deployment, so owner id will point to Deployment's uuid.
	owners map[string]*imageOwner
	nodes  map[string]*imageNode

	// ownerChanges holds temp state for tracking changed image owners. We use this state to notify CAST AI about changed resources.
	ownerChanges ownerChanges

	scanned      bool
	lastScanErr  error
	failures     int          // Used for sorting. We want to scan non-failed images first.
	retryBackoff wait.Backoff // Retry state for failed images.
	nextScan     time.Time    // Set based on retry backoff.

	lastRemoteSyncAt time.Time // Time then image state was synced from remote.
}

func (img *image) cacheKey() string {
	return img.id + img.architecture
}

func (img *image) isUnused() bool {
	return len(img.nodes) == 0 && len(img.owners) == 0
}

type ownerChanges struct {
	addedIDS []string
}

func (c *ownerChanges) empty() bool {
	return len(c.addedIDS) == 0
}

func (c *ownerChanges) clear() {
	c.addedIDS = []string{}
}
