package kube

import (
	"context"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/castai/kvisor/pkg/logging"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/cache"
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
	RequiredTypes() []reflect.Type
}

type Client struct {
	log                           *logging.Logger
	kvisorNamespace               string
	podName                       string
	kvisorControllerContainerName string
	client                        kubernetes.Interface

	mu                      sync.RWMutex
	replicaSets             map[types.UID]metav1.ObjectMeta
	jobs                    map[types.UID]metav1.ObjectMeta
	deployments             map[types.UID]*appsv1.Deployment
	kvisorControllerPodSpec *corev1.PodSpec

	changeListenersMu sync.RWMutex
	changeListeners   []*eventListener
	version           Version
}

func NewClient(
	log *logging.Logger,
	podName, kvisorNamespace string,
	version Version,
	client kubernetes.Interface,
) *Client {
	return &Client{
		log:                           log.WithField("component", "kube_watcher"),
		kvisorNamespace:               kvisorNamespace,
		podName:                       podName,
		kvisorControllerContainerName: "controller",
		client:                        client,
		replicaSets:                   map[types.UID]metav1.ObjectMeta{},
		jobs:                          map[types.UID]metav1.ObjectMeta{},
		deployments:                   map[types.UID]*appsv1.Deployment{},
		version:                       version,
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
	if err := podsInformer.SetTransform(c.transformFunc); err != nil {
		panic(err)
	}
	if _, err := podsInformer.AddEventHandler(c.eventHandler()); err != nil {
		panic(err)
	}
}

func (c *Client) Run(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Client) eventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			c.mu.Lock()
			defer c.mu.Unlock()

			switch t := obj.(type) {
			case *batchv1.Job:
				c.jobs[t.UID] = t.ObjectMeta
			case *appsv1.ReplicaSet:
				c.replicaSets[t.UID] = t.ObjectMeta
			case *appsv1.Deployment:
				c.deployments[t.UID] = t
			}

			if kubeObj, ok := obj.(Object); ok {
				c.fireKubernetesAddEvent(kubeObj)
			}
		},
		UpdateFunc: func(oldObj, newObj any) {
			c.mu.Lock()
			defer c.mu.Unlock()

			switch t := newObj.(type) {
			case *batchv1.Job:
				c.jobs[t.UID] = t.ObjectMeta
			case *appsv1.ReplicaSet:
				c.replicaSets[t.UID] = t.ObjectMeta
			case *appsv1.Deployment:
				c.deployments[t.UID] = t
			}

			if kubeObj, ok := newObj.(Object); ok {
				c.fireKubernetesUpdateEvent(kubeObj)
			}
		},
		DeleteFunc: func(obj interface{}) {
			c.mu.Lock()
			defer c.mu.Unlock()

			switch t := obj.(type) {
			case *batchv1.Job:
				delete(c.jobs, t.UID)
			case *appsv1.ReplicaSet:
				delete(c.replicaSets, t.UID)
			case *appsv1.Deployment:
				delete(c.deployments, t.UID)
			}

			if kubeObj, ok := obj.(Object); ok {
				c.fireKubernetesDeleteEvent(kubeObj)
			}
		},
	}
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

func findOwnerFromDeployments(workloads map[types.UID]*appsv1.Deployment, pod *corev1.Pod) (types.UID, bool) {
	for _, w := range workloads {

		sel, err := metav1.LabelSelectorAsSelector(w.Spec.Selector)
		if err != nil {
			continue
		}
		if sel.Matches(labels.Set(pod.Labels)) {
			return w.UID, true
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
		if owner, found := findOwnerFromDeployments(c.deployments, pod); found {
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
	c.mu.RLock()
	defer c.mu.RUnlock()

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
	AgentImageName   string
	ImagePullSecrets []corev1.LocalObjectReference
}

// GetKvisorAgentImageDetails returns kvisor agent image details.
// This is used for image analyzer and kube-bench dynamic jobs to schedule using the same image.
func (c *Client) GetKvisorAgentImageDetails() (ImageDetails, bool) {
	spec, found := c.getKvisorControllerPodSpec()
	if !found {
		c.log.Warn("kvisor controller pod spec not found")
		return ImageDetails{}, false
	}
	var imageName string
	for _, container := range spec.Containers {
		if container.Name == c.kvisorControllerContainerName {
			imageName = container.Image
			break
		}
	}
	if imageName == "" {
		c.log.Warn("kvisor container image not found")
		return ImageDetails{}, false
	}
	return ImageDetails{
		AgentImageName:   strings.Replace(imageName, "-controller", "-agent", 1),
		ImagePullSecrets: spec.ImagePullSecrets,
	}, true
}

func (c *Client) getKvisorControllerPodSpec() (*corev1.PodSpec, bool) {
	c.mu.RLock()
	spec := c.kvisorControllerPodSpec
	c.mu.RUnlock()
	if spec != nil {
		return spec, true
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pod, err := c.client.CoreV1().Pods(c.kvisorNamespace).Get(ctx, c.podName, metav1.GetOptions{})
	if err != nil {
		return nil, false
	}

	c.mu.Lock()
	c.kvisorControllerPodSpec = &pod.Spec
	c.mu.Unlock()

	return &pod.Spec, true
}

func (c *Client) RegisterKubernetesChangeListener(l KubernetesChangeEventListener) {
	c.changeListenersMu.Lock()
	defer c.changeListenersMu.Unlock()

	requiredTypes := l.RequiredTypes()
	internalListener := &eventListener{
		lis:           l,
		requiredTypes: make(map[reflect.Type]struct{}, len(requiredTypes)),
	}
	for _, t := range requiredTypes {
		internalListener.requiredTypes[t] = struct{}{}
	}
	c.changeListeners = append(c.changeListeners, internalListener)
}

func (c *Client) fireKubernetesAddEvent(obj Object) {
	c.changeListenersMu.RLock()
	listeners := c.changeListeners
	c.changeListenersMu.RUnlock()

	for _, l := range listeners {
		if l.required(obj) {
			go l.lis.OnAdd(obj)
		}
	}
}

func (c *Client) fireKubernetesUpdateEvent(obj Object) {
	c.changeListenersMu.RLock()
	listeners := c.changeListeners
	c.changeListenersMu.RUnlock()

	for _, l := range listeners {
		if l.required(obj) {
			go l.lis.OnUpdate(obj)
		}
	}
}

func (c *Client) fireKubernetesDeleteEvent(obj Object) {
	c.changeListenersMu.RLock()
	listeners := c.changeListeners
	c.changeListenersMu.RUnlock()

	for _, l := range listeners {
		if l.required(obj) {
			go l.lis.OnDelete(obj)
		}
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
// See one of many issues related to this https://github.com/kubernetes/kubernetes/issues/80609
func addObjectMeta(o Object) {
	gvks, _, _ := scheme.Scheme.ObjectKinds(o)
	if len(gvks) > 0 {
		o.GetObjectKind().SetGroupVersionKind(gvks[0])
	}
}

type eventListener struct {
	lis           KubernetesChangeEventListener
	requiredTypes map[reflect.Type]struct{}
}

func (e *eventListener) required(obj Object) bool {
	_, found := e.requiredTypes[reflect.TypeOf(obj)]
	return found
}
