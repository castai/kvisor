package kube

import (
	"context"
	"sync"
	"time"

	"github.com/castai/kvisor/pkg/logging"
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

	gcInterval        time.Duration
	mu                sync.RWMutex
	replicaSets       map[types.UID]metav1.ObjectMeta
	jobs              map[types.UID]metav1.ObjectMeta
	deployments       map[types.UID]*appsv1.Deployment
	kvisorAgentDsSpec *appsv1.DaemonSetSpec

	changeListenersMu sync.RWMutex
	changeListeners   []KubernetesChangeEventListener
	version           Version
}

func NewClient(
	log *logging.Logger,
	kvisorAgentDaemonSetName, kvisorNamespace string,
	version Version,
	client kubernetes.Interface,
) *Client {
	return &Client{
		log:                      log.WithField("component", "kube_watcher"),
		kvisorNamespace:          kvisorNamespace,
		kvisorAgentDaemonSetName: kvisorAgentDaemonSetName,
		kvisorAgentContainerName: "kvisor",
		client:                   client,
		gcInterval:               1 * time.Minute,
		replicaSets:              map[types.UID]metav1.ObjectMeta{},
		jobs:                     map[types.UID]metav1.ObjectMeta{},
		deployments:              map[types.UID]*appsv1.Deployment{},
		version:                  version,
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
	select {
	case <-ctx.Done():
		return ctx.Err()
	}
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
			//w.log.Debugf("update %T", newObj)
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
			//w.log.Debugf("delete %T", obj)
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

func (c *Client) getKvisorAgentDaemonSpec() (*appsv1.DaemonSetSpec, bool) {
	c.mu.RLock()
	spec := c.kvisorAgentDsSpec
	c.mu.RUnlock()
	if spec != nil {
		return spec, true
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ds, err := c.client.AppsV1().DaemonSets(c.kvisorNamespace).Get(ctx, c.kvisorAgentDaemonSetName, metav1.GetOptions{})
	if err != nil {
		return nil, false
	}

	c.mu.Lock()
	c.kvisorAgentDsSpec = &ds.Spec
	c.mu.Unlock()

	return &ds.Spec, true
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
