package kube

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/castai/kvisor/pkg/logging"
	"github.com/samber/lo"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

var (
	ErrNotFound = errors.New("object not found")
)

type EventType string

const (
	EventAdd    EventType = "add"
	EventUpdate EventType = "update"
	EventDelete EventType = "delete"
)

type Object interface {
	runtime.Object
	metav1.Object
}

type KubernetesChangeEventListener interface {
	OnAdd(obj Object)
	OnDelete(obj Object)
	OnUpdate(newObj Object)
}

type Client struct {
	log                      *logging.Logger
	kvisorNamespace          string
	kvisorAgentDaemonSetName string
	kvisorAgentContainerName string
	client                   kubernetes.Interface
	ipInventory              *IPInventory

	issues      chan Issue
	gcInterval  time.Duration
	mu          sync.RWMutex
	replicaSets map[types.UID]metav1.ObjectMeta
	jobs        map[types.UID]metav1.ObjectMeta
	pods        map[types.UID]*Pod
	workloads   map[string]*Workload
	nodesByName map[string]*corev1.Node

	podByContainerID map[string]*Pod

	changeListenersMu sync.RWMutex
	changeListeners   []KubernetesChangeEventListener
	version           Version
}

func NewClient(
	log *logging.Logger,
	kvisorAgentDaemonSetName, kvisorNamespace string,
	version Version,
	client kubernetes.Interface,
	ipInventory *IPInventory,
) *Client {
	return &Client{
		log:                      log.WithField("component", "kube_watcher"),
		kvisorNamespace:          kvisorNamespace,
		kvisorAgentDaemonSetName: kvisorAgentDaemonSetName,
		kvisorAgentContainerName: "kvisor",
		version:                  version,
		client:                   client,
		ipInventory:              ipInventory,
		issues:                   make(chan Issue, 1000),
		gcInterval:               1 * time.Minute,
		replicaSets:              map[types.UID]metav1.ObjectMeta{},
		jobs:                     map[types.UID]metav1.ObjectMeta{},
		pods:                     map[types.UID]*Pod{},
		podByContainerID:         map[string]*Pod{},
		workloads:                map[string]*Workload{},
		nodesByName:              map[string]*corev1.Node{},
	}
}

func (c *Client) RegisterHandlers(factory informers.SharedInformerFactory) {
	informersList := []cache.SharedInformer{
		factory.Core().V1().Nodes().Informer(),
		factory.Core().V1().Services().Informer(),
		factory.Core().V1().Endpoints().Informer(),
		factory.Core().V1().Namespaces().Informer(),
		factory.Apps().V1().Deployments().Informer(),
		factory.Apps().V1().StatefulSets().Informer(),
		factory.Apps().V1().DaemonSets().Informer(),
		factory.Apps().V1().ReplicaSets().Informer(),
		factory.Batch().V1().CronJobs().Informer(),
		factory.Batch().V1().Jobs().Informer(),
		factory.Rbac().V1().ClusterRoles().Informer(),
		factory.Rbac().V1().Roles().Informer(),
		factory.Rbac().V1().ClusterRoleBindings().Informer(),
		factory.Rbac().V1().RoleBindings().Informer(),
		factory.Networking().V1().NetworkPolicies().Informer(),
		factory.Networking().V1().Ingresses().Informer(),
	}

	if c.version.MinorInt >= 21 {
		informersList = append(informersList, factory.Batch().V1().CronJobs().Informer())
	} else {
		informersList = append(informersList, factory.Batch().V1beta1().CronJobs().Informer())
	}

	for _, informer := range informersList {
		if err := informer.SetTransform(c.transformFunc); err != nil {
			panic(err)
		}
		if _, err := informer.AddEventHandler(c.eventHandler()); err != nil {
			panic(err)
		}
	}
}

func (c *Client) RegisterPodsHandlers(factory informers.SharedInformerFactory) {
	podsInformer := factory.Core().V1().Pods().Informer()
	if _, err := podsInformer.AddEventHandler(c.eventHandler()); err != nil {
		panic(err)
	}
}

func (c *Client) Run(ctx context.Context) error {
	return c.startGC(ctx)
}

func (c *Client) GetIssuesChan() <-chan Issue {
	return c.issues
}

func (c *Client) GetPodByContainerID(containerID string) (*Pod, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if v, ok := c.podByContainerID[containerID]; ok {
		return v, nil
	}
	return nil, ErrNotFound
}

func (c *Client) GetPodByUID(uid string) (*Pod, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if v, ok := c.pods[types.UID(uid)]; ok {
		return v, nil
	}
	return nil, ErrNotFound
}

func (c *Client) ListPods() []*Pod {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return lo.Values(c.pods)
}

func (c *Client) ListWorkloads() []*Workload {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return lo.Values(c.workloads)
}

func (c *Client) GetWorkloadPodTemplate(key string) (*corev1.PodTemplateSpec, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	workload, found := c.workloads[key]
	if !found {
		return nil, ErrNotFound
	}
	switch t := workload.Object.(type) {
	case *appsv1.Deployment:
		return t.Spec.Template.DeepCopy(), nil
	case *appsv1.StatefulSet:
		return t.Spec.Template.DeepCopy(), nil
	case *appsv1.DaemonSet:
		return t.Spec.Template.DeepCopy(), nil
	case *batchv1.CronJob:
		return t.Spec.JobTemplate.Spec.Template.DeepCopy(), nil
	}
	return nil, ErrNotFound
}

func (c *Client) GetNodeByName(name string) (*corev1.Node, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if v, ok := c.nodesByName[name]; ok {
		return v, nil
	}
	return nil, ErrNotFound
}

func (c *Client) ListNamespaces(ctx context.Context) ([]corev1.Namespace, error) {
	nsList, err := c.client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return nsList.Items, nil
}

func (c *Client) eventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			c.mu.Lock()
			defer c.mu.Unlock()

			switch t := obj.(type) {
			case *corev1.Node:
				c.nodesByName[t.Name] = t
				c.ipInventory.add(t)
			case *appsv1.Deployment:
				workload := newWorkload("Deployment", t.ObjectMeta)
				workload.Replicas = int(lo.FromPtr(t.Spec.Replicas))
				workload.Object = t
				c.workloads[string(t.UID)] = workload
			case *appsv1.StatefulSet:
				workload := newWorkload("StatefulSet", t.ObjectMeta)
				workload.Object = t
				workload.Replicas = int(lo.FromPtr(t.Spec.Replicas))
				c.workloads[string(t.UID)] = workload
			case *appsv1.DaemonSet:
				workload := newWorkload("DaemonSet", t.ObjectMeta)
				workload.Object = t
				workload.Replicas = int(t.Status.DesiredNumberScheduled)
				c.workloads[string(t.UID)] = workload
			case *batchv1.CronJob:
				workload := newWorkload("CronJob", t.ObjectMeta)
				workload.Object = t
				c.workloads[string(t.UID)] = workload
			case *batchv1.Job:
				c.jobs[t.UID] = t.ObjectMeta
			case *appsv1.ReplicaSet:
				c.replicaSets[t.UID] = t.ObjectMeta
			case *corev1.Service:
				c.ipInventory.add(t)
			case *corev1.Endpoints:
				c.ipInventory.add(t)
			case *corev1.Pod:
				pod := c.addPod(t)
				c.addContainerIndex(pod)
				c.addWorkloadReference(t, pod)
				c.ipInventory.add(pod)
			}

			if kubeObj, ok := obj.(Object); ok {
				c.fireKubernetesAddEvent(kubeObj)
			}
		},
		UpdateFunc: func(oldObj, newObj any) {
			//w.log.Debugf("update %T", newObj)
			c.mu.Lock()
			defer c.mu.Unlock()

			switch t := newObj.(type) {
			case *corev1.Node:
				c.nodesByName[t.Name] = t
				c.ipInventory.add(t)
			case *appsv1.Deployment:
				if workload, found := c.workloads[string(t.UID)]; found {
					workload.Object = t
					workload.Replicas = int(lo.FromPtr(t.Spec.Replicas))
				}
			case *appsv1.StatefulSet:
				if workload, found := c.workloads[string(t.UID)]; found {
					workload.Object = t
					workload.Replicas = int(lo.FromPtr(t.Spec.Replicas))
				}
			case *appsv1.DaemonSet:
				if workload, found := c.workloads[string(t.UID)]; found {
					workload.Object = t
					workload.Replicas = int(t.Status.DesiredNumberScheduled)
				}
			case *batchv1.CronJob:
				if workload, found := c.workloads[string(t.UID)]; found {
					workload.Object = t
				}
			case *batchv1.Job:
				c.jobs[t.UID] = t.ObjectMeta
			case *corev1.Service:
				c.ipInventory.add(t)
			case *corev1.Endpoints:
				c.ipInventory.add(t)
			case *corev1.Pod:
				if v, ok := c.pods[t.UID]; ok {
					c.updatePod(v, t)
					c.addContainerIndex(v)
					c.ipInventory.add(v)
					c.addWorkloadReference(t, v)
					c.detectIssues(v)
				}
			}

			if kubeObj, ok := newObj.(Object); ok {
				c.fireKubernetesUpdateEvent(kubeObj)
			}
		},
		DeleteFunc: func(obj interface{}) {
			//w.log.Debugf("delete %T", obj)
			c.mu.Lock()
			defer c.mu.Unlock()

			switch t := obj.(type) {
			case *corev1.Node:
				delete(c.nodesByName, t.Name)
				c.ipInventory.delete(t)
			case *appsv1.Deployment:
				delete(c.workloads, string(t.UID))
			case *appsv1.StatefulSet:
				delete(c.workloads, string(t.UID))
			case *appsv1.DaemonSet:
				delete(c.workloads, string(t.UID))
			case *batchv1.CronJob:
				delete(c.workloads, string(t.UID))
			case *batchv1.Job:
				delete(c.jobs, t.UID)
			case *appsv1.ReplicaSet:
				delete(c.replicaSets, t.UID)
			case *corev1.Service:
				c.ipInventory.delete(t)
			case *corev1.Endpoints:
				c.ipInventory.delete(t)
			case *corev1.Pod:
				if v, ok := c.pods[t.UID]; ok {
					v.DeletionTimestamp = lo.ToPtr(time.Now().UTC())
				}
			}

			if kubeObj, ok := obj.(Object); ok {
				c.fireKubernetesDeleteEvent(kubeObj)
			}
		},
	}
}

func (c *Client) addWorkloadReference(t *corev1.Pod, pod *Pod) {
	wkey := c.getPodWorkloadKey(t)
	wk, found := c.workloads[wkey]
	if found {
		pod.Workload = wk
	}
}

func (c *Client) addContainerIndex(pod *Pod) {
	for _, cont := range pod.Pod.Status.InitContainerStatuses {
		cont := cont
		if cont.ContainerID == "" {
			continue
		}
		cid := GetContainerID(cont.ContainerID)
		c.podByContainerID[cid] = pod
		pod.Containers[cid] = &cont
	}

	for _, cont := range pod.Pod.Status.ContainerStatuses {
		cont := cont
		if cont.ContainerID == "" {
			continue
		}
		cid := GetContainerID(cont.ContainerID)
		c.podByContainerID[cid] = pod
		pod.Containers[cid] = &cont
	}
}

func (c *Client) startGC(ctx context.Context) error {
	t := time.NewTicker(c.gcInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			c.runGC()
		}
	}
}

func (c *Client) runGC() {
	c.mu.Lock()
	defer c.mu.Unlock()

	deleteBefore := time.Now().UTC().Add(-c.gcInterval)
	var deletedPods int
	var deletedContainers int

	for _, v := range c.pods {
		if dts := v.DeletionTimestamp; dts != nil {
			ts := dts
			if ts.Before(deleteBefore) {
				delete(c.pods, v.Pod.UID)
				c.ipInventory.delete(v)
				deletedPods++
				for contID, pod := range c.podByContainerID {
					if pod.Pod.UID == v.Pod.UID {
						delete(c.podByContainerID, GetContainerID(contID))
						deletedContainers++
					}
				}
			}
		}
	}

	c.log.Debugf("kube watcher gc done, deleted_pods=%d, deleted_containers=%d", deletedPods, deletedContainers)
}

func (c *Client) getPodWorkloadKey(pod *corev1.Pod) string {
	if len(pod.OwnerReferences) > 0 {
		ref := pod.OwnerReferences[0]
		switch ref.Kind {
		// If replica set points to deployment we need to find deployment's uid.
		case "ReplicaSet":
			rs, found := c.replicaSets[ref.UID]
			if !found {
				return string(ref.UID)
			}
			// Most likely replica set is managed by Deployment.
			if len(rs.OwnerReferences) > 0 {
				ref = rs.OwnerReferences[0]
				return string(ref.UID)
			}
		case "Job":
			cr, found := c.jobs[ref.UID]
			if !found {
				return getStandalonePodWorkloadKey(pod.ObjectMeta, pod.Spec.Containers)
			}
			// Most likely job is managed by CronJob.
			if len(cr.OwnerReferences) > 0 {
				ref = cr.OwnerReferences[0]
				return string(ref.UID)
			}
		default:
			return string(ref.UID)
		}
	}
	return getStandalonePodWorkloadKey(pod.ObjectMeta, pod.Spec.Containers)
}

func (c *Client) addPod(t *corev1.Pod) *Pod {
	pod := &Pod{
		Pod:        t,
		Containers: map[string]*corev1.ContainerStatus{},
	}
	c.pods[t.UID] = pod

	return pod
}

func (c *Client) updatePod(v *Pod, t *corev1.Pod) {
	v.Pod = t
	if v.Zone == "" {
		if node, found := c.nodesByName[t.Spec.NodeName]; found {
			v.Zone = getNodeZone(node)
		}
	}
}

type Pod struct {
	Pod               *corev1.Pod
	Zone              string
	Workload          *Workload
	Containers        map[string]*corev1.ContainerStatus
	DeletionTimestamp *time.Time
}

func GetContainerID(id string) string {
	_, after, _ := strings.Cut(id, "//")
	return after
}

type Workload struct {
	Key       string
	Namespace string
	Kind      string
	Name      string
	Replicas  int
	Object    runtime.Object
}

func newWorkload(kind string, meta metav1.ObjectMeta) *Workload {
	return &Workload{
		Key:       string(meta.UID),
		Namespace: meta.Namespace,
		Kind:      kind,
		Name:      meta.Name,
	}
}

// getStandalonePodWorkloadKey for single jobs or standalone pods we can't use uid as it will be random each time.
// In such case it would generate too many workload profiles.
func getStandalonePodWorkloadKey(meta metav1.ObjectMeta, containers []corev1.Container) string {
	contNames := make([]string, len(containers))
	for i, cont := range containers {
		contNames[i] = cont.Name
	}
	sort.Strings(contNames)
	return fmt.Sprintf("%s-%s", meta.Namespace, strings.Join(contNames, "-"))
}

func getNodeZone(node *corev1.Node) string {
	return node.Labels["topology.kubernetes.io/zone"]
}

func findNextOwnerID(obj metav1.ObjectMeta, expectedKind string) (types.UID, bool) {
	refs := obj.GetOwnerReferences()
	if len(refs) == 0 {
		return obj.GetUID(), true
	}

	for _, ref := range refs {
		if ref.Kind == expectedKind {
			return ref.UID, true
		}
	}

	return "", false
}

func findOwnerFromDeployments(workloads map[string]*Workload, pod *corev1.Pod) (types.UID, bool) {
	for _, w := range workloads {
		deployment, ok := w.Object.(*appsv1.Deployment)
		if !ok {
			continue
		}

		sel, err := metav1.LabelSelectorAsSelector(deployment.Spec.Selector)
		if err != nil {
			continue
		}
		if sel.Matches(labels.Set(pod.Labels)) {
			return deployment.UID, true
		}
	}
	return "", false
}

func (c *Client) getPodOwnerID(pod *corev1.Pod) string {
	if len(pod.OwnerReferences) == 0 {
		return string(pod.UID)
	}
	ref := pod.OwnerReferences[0]

	switch ref.Kind {
	case "DaemonSet", "StatefulSet":
		return string(ref.UID)
	case "ReplicaSet":
		rs, found := c.replicaSets[ref.UID]
		if found {
			// Fast path. Find Deployment from replica set.
			if owner, found := findNextOwnerID(rs, "Deployment"); found {
				return string(owner)
			}
		}

		// Slow path. Find deployment by matching selectors.
		// In this Deployment could be managed by some crd like ArgoRollouts.
		if owner, found := findOwnerFromDeployments(c.workloads, pod); found {
			return string(owner)
		}

		if found {
			return string(rs.UID)
		}
	case "Job":
		job, found := c.jobs[ref.UID]
		if found {
			if owner, found := findNextOwnerID(job, "CronJob"); found {
				return string(owner)
			}
			return string(job.UID)
		}
	}

	return string(pod.UID)
}

func (c *Client) GetOwnerUID(obj Object) string {
	switch v := obj.(type) {
	case *corev1.Pod:
		return c.getPodOwnerID(v)
	}

	if len(obj.GetOwnerReferences()) == 0 {
		return ""
	}
	return string(obj.GetOwnerReferences()[0].UID)
}

type ImageDetails struct {
	ImageName        string
	ImagePullSecrets []corev1.LocalObjectReference
}

// GetKvisorAgentImageDetails returns kvisor image details.
// This is used for image analyzer and kube-bench dynamic jobs to schedule using the same image.
func (c *Client) GetKvisorAgentImageDetails() (ImageDetails, bool) {
	spec, found := c.getKvisorAgentDaemonSpec()
	if !found {
		c.log.Warn("kvisor agent daemon set not found")
		return ImageDetails{}, false
	}
	var imageName string
	for _, container := range spec.Template.Spec.Containers {
		if container.Name == c.kvisorAgentContainerName {
			imageName = container.Image
			break
		}
	}
	if imageName == "" {
		c.log.Warn("kvisor container image not found")
		return ImageDetails{}, false
	}
	return ImageDetails{
		ImageName:        imageName,
		ImagePullSecrets: spec.Template.Spec.ImagePullSecrets,
	}, true
}

func (c *Client) getKvisorAgentDaemonSpec() (appsv1.DaemonSetSpec, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, w := range c.workloads {
		ds, ok := w.Object.(*appsv1.DaemonSet)
		if !ok {
			continue
		}
		if w.Namespace == c.kvisorNamespace && w.Name == c.kvisorAgentDaemonSetName {
			return ds.Spec, true
		}
	}
	return appsv1.DaemonSetSpec{}, false
}

func (c *Client) RegisterKubernetesChangeListener(l KubernetesChangeEventListener) {
	c.changeListenersMu.Lock()
	defer c.changeListenersMu.Unlock()

	c.changeListeners = append(c.changeListeners, l)
}

func (c *Client) fireKubernetesAddEvent(obj Object) {
	c.changeListenersMu.RLock()
	listeners := c.changeListeners
	c.changeListenersMu.RUnlock()

	for _, l := range listeners {
		go l.OnAdd(obj)
	}
}

func (c *Client) fireKubernetesUpdateEvent(obj Object) {
	c.changeListenersMu.RLock()
	listeners := c.changeListeners
	c.changeListenersMu.RUnlock()

	for _, l := range listeners {
		go l.OnUpdate(obj)
	}
}

func (c *Client) fireKubernetesDeleteEvent(obj Object) {
	c.changeListenersMu.RLock()
	listeners := c.changeListeners
	c.changeListenersMu.RUnlock()

	for _, l := range listeners {
		go l.OnDelete(obj)
	}
}

func (c *Client) transformFunc(i any) (any, error) {
	obj := i.(Object)
	// Add missing metadata which is removed by k8s.
	addObjectMeta(obj)
	// Remove managed fields since we don't need them. This should decrease memory usage.
	obj.SetManagedFields(nil)
	return obj, nil
}

// addObjectMeta adds missing metadata since kubernetes client removes object kind and api version information.
func addObjectMeta(o Object) {
	appsV1 := "apps/v1"
	v1 := "v1"
	switch o := o.(type) {
	case *appsv1.Deployment:
		o.Kind = "Deployment"
		o.APIVersion = appsV1
	case *appsv1.ReplicaSet:
		o.Kind = "ReplicaSet"
		o.APIVersion = appsV1
	case *appsv1.StatefulSet:
		o.Kind = "StatefulSet"
		o.APIVersion = appsV1
	case *appsv1.DaemonSet:
		o.Kind = "DaemonSet"
		o.APIVersion = appsV1
	case *corev1.Node:
		o.Kind = "Node"
		o.APIVersion = v1
	case *corev1.Namespace:
		o.Kind = "Namespace"
		o.APIVersion = v1
	case *corev1.Service:
		o.Kind = "Service"
		o.APIVersion = v1
	case *corev1.Pod:
		o.Kind = "Pod"
		o.APIVersion = v1
	case *rbacv1.ClusterRoleBinding:
		o.Kind = "ClusterRoleBinding"
		o.APIVersion = "rbac.authorization.k8s.io/v1"
	case *rbacv1.RoleBinding:
		o.Kind = "RoleBinding"
		o.APIVersion = "rbac.authorization.k8s.io/v1"
	case *rbacv1.ClusterRole:
		o.Kind = "ClusterRole"
		o.APIVersion = "rbac.authorization.k8s.io/v1"
	case *rbacv1.Role:
		o.Kind = "Role"
		o.APIVersion = "rbac.authorization.k8s.io/v1"
	case *batchv1.Job:
		o.Kind = "Job"
		o.APIVersion = "batch/v1"
	case *batchv1.CronJob:
		o.Kind = "CronJob"
		o.APIVersion = "batch/v1"
	case *batchv1beta1.CronJob:
		o.Kind = "CronJob"
		o.APIVersion = "batch/v1beta1"
	case *networkingv1.Ingress:
		o.Kind = "Ingress"
		o.APIVersion = "networking/v1"
	case *networkingv1.NetworkPolicy:
		o.Kind = "NetworkPolicy"
		o.APIVersion = "networking/v1"
	}
}
