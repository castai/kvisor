package imagescan

import (
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/samber/lo"
	"gopkg.in/inf.v0"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/castai/kvisor/castai"
	imgcollectorconfig "github.com/castai/kvisor/cmd/imgcollector/config"
	"github.com/castai/kvisor/controller"
)

var (
	errNoCandidates = errors.New("no candidates")
)

func buildImageMap(scannedImages []castai.ScannedImage) map[string]*image {
	images := map[string]*image{}
	for _, scannedImage := range scannedImages {
		owners := make(map[string]*imageOwner, len(scannedImage.ResourceIDs))
		for _, id := range scannedImage.ResourceIDs {
			owners[id] = &imageOwner{
				podIDs: map[string]struct{}{},
			}
		}

		img := newImage(scannedImage.ID, scannedImage.Architecture)
		img.scanned = true
		img.owners = owners
		img.architecture = scannedImage.Architecture
		images[scannedImage.CacheKey()] = img
	}

	return images
}

func newImage(imageID, architecture string) *image {
	return &image{
		id:           imageID,
		architecture: architecture,
		owners:       map[string]*imageOwner{},
		nodes:        map[string]*imageNode{},
		scanned:      false,
		retryBackoff: wait.Backoff{
			Duration: time.Second * 60,
			Factor:   3,
			Steps:    8,
		},
	}
}

func NewDeltaState(scannedImages []castai.ScannedImage) *deltaState {
	return &deltaState{
		images: buildImageMap(scannedImages),
		rs:     make(map[string]*appsv1.ReplicaSet),
		jobs:   make(map[string]*batchv1.Job),
		nodes:  map[string]*node{},
	}
}

type deltaState struct {
	mu     sync.RWMutex
	images map[string]*image
	rs     map[string]*appsv1.ReplicaSet
	jobs   map[string]*batchv1.Job
	nodes  map[string]*node
}

func (d *deltaState) Observe(response *castai.TelemetryResponse) {
	if response.FullResync && len(response.ScannedImages) > 0 {
		d.mu.Lock()
		defer d.mu.Unlock()
		// sync with servers state
		d.images = buildImageMap(response.ScannedImages)
		d.rs = make(map[string]*appsv1.ReplicaSet)
		d.jobs = make(map[string]*batchv1.Job)
		d.nodes = map[string]*node{}
	}
}

func (d *deltaState) upsert(o controller.Object) {
	d.mu.Lock()
	defer d.mu.Unlock()

	key := controller.ObjectKey(o)
	switch v := o.(type) {
	case *corev1.Pod:
		d.handlePodUpdate(v)
	case *corev1.Node:
		d.updateNodeUsage(v)
	case *batchv1.Job:
		d.jobs[key] = v
	case *appsv1.ReplicaSet:
		d.rs[key] = v
	}
}

func (d *deltaState) delete(o controller.Object) {
	d.mu.Lock()
	defer d.mu.Unlock()

	key := controller.ObjectKey(o)
	switch v := o.(type) {
	case *corev1.Pod:
		d.handlePodDelete(v)
	case *corev1.Node:
		d.handleNodeDelete(v)
	case *batchv1.Job:
		delete(d.jobs, key)
	case *appsv1.ReplicaSet:
		delete(d.rs, key)
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
			n = &node{
				name:           v.Spec.NodeName,
				allocatableMem: &inf.Dec{},
				allocatableCPU: &inf.Dec{},
				pods:           make(map[types.UID]*pod),
			}
			d.nodes[v.Spec.NodeName] = n
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
	// get the resource id of Deployment, ReplicaSet, StatefulSet, Job, CronJob
	ownerResourceID := getPodOwnerID(pod, d.rs, d.jobs)

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

		arch := "amd64"
		nodeName := pod.Spec.NodeName
		n, ok := d.nodes[nodeName]
		if ok {
			arch = n.architecture
		}

		key := cs.ImageID + arch
		img, found := d.images[key]
		if !found {
			img = newImage(cs.ImageID, arch)
		}
		img.id = cs.ImageID
		img.name = cont.Image
		img.containerRuntime = getContainerRuntime(cs.ContainerID)

		if owner, found := img.owners[ownerResourceID]; found {
			// resources not changed because Resources we send are actually keys of img.owners and nothing changed there.
			owner.podIDs[podID] = struct{}{}
		} else {
			img.owners[ownerResourceID] = &imageOwner{
				podIDs: map[string]struct{}{
					podID: {},
				},
			}
		}

		if n, found := img.nodes[nodeName]; found {
			// resources not changed because Resources we send are actually keys of img.owners and nothing changed there.
			n.podIDs[podID] = struct{}{}
		} else {
			// resources not changed because Resources we send are actually keys of img.owners and nothing changed there.
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
		podID := string(pod.UID)
		if n, found := img.nodes[pod.Spec.NodeName]; found {
			delete(n.podIDs, podID)
		}

		ownerResourceID := getPodOwnerID(pod, d.rs, d.jobs)
		if owner, found := img.owners[ownerResourceID]; found {
			delete(owner.podIDs, podID)
			if len(owner.podIDs) == 0 {
				// resource did not change because backend should already know about image, there will be no new scan.
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
	d.mu.RLock()
	defer d.mu.RUnlock()

	return lo.Values(d.images)
}

func (d *deltaState) getNode(name string) (*node, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	v, found := d.nodes[name]
	return v, found
}

func (d *deltaState) updateImage(i *image, change func(img *image)) {
	d.mu.Lock()
	defer d.mu.Unlock()

	img := d.images[i.cacheKey()]
	if img != nil {
		change(img)
	}
}

func (d *deltaState) setImageScanError(i *image, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	img := d.images[i.cacheKey()]
	if img == nil {
		return
	}

	img.failures++
	img.lastScanErr = err
	if strings.Contains(err.Error(), "no such file or directory") {
		img.lastScanErr = errImageScanLayerNotFound
	}

	img.nextScan = time.Now().UTC().Add(img.retryBackoff.Step())
}

func (d *deltaState) findBestNode(nodeNames []string, requiredMemory *inf.Dec, requiredCPU *inf.Dec) (string, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if len(d.nodes) == 0 {
		return "", errNoCandidates
	}

	var candidates []*node
	for _, nodeName := range nodeNames {
		if n, found := d.nodes[nodeName]; found && n.availableMemory().Cmp(requiredMemory) >= 0 && n.availableCPU().Cmp(requiredCPU) >= 0 {
			candidates = append(candidates, d.nodes[nodeName])
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
	d.mu.RLock()
	defer d.mu.RUnlock()

	return len(d.nodes)
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

var errImageScanLayerNotFound = errors.New("image layer not found")

type image struct {
	id               string
	architecture     string
	name             string
	containerRuntime imgcollectorconfig.Runtime
	owners           map[string]*imageOwner
	nodes            map[string]*imageNode

	scanned      bool
	lastScanErr  error
	failures     int          // Used for sorting. We want to scan non-failed images first.
	retryBackoff wait.Backoff // Retry state for failed images.
	nextScan     time.Time    // Set based on retry backoff.
}

func (img *image) cacheKey() string {
	return img.id + img.architecture
}

func (img *image) isUnused() bool {
	return len(img.nodes) == 0 && len(img.owners) == 0
}
