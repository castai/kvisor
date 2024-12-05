package kube

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/castai/kvisor/pkg/logging"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

type AddListener interface {
	OnAdd(obj Object)
}

type UpdateListener interface {
	OnUpdate(obj Object)
}

type DeleteListener interface {
	OnDelete(obj Object)
}

type KubernetesChangeEventListener interface {
	RequiredTypes() []reflect.Type
}

type Client struct {
	log                           *logging.Logger
	kvisorNamespace               string
	podName                       string
	kvisorControllerContainerName string
	client                        kubernetes.Interface

	mu                      sync.RWMutex
	kvisorControllerPodSpec *corev1.PodSpec

	index *Index

	clusterInfo *ClusterInfo

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
		index:                         NewIndex(),
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
			case *corev1.Pod:
				c.index.addFromPod(t)
			case *corev1.Service:
				c.index.addFromService(t)
			case *corev1.Endpoints:
				c.index.addFromEndpoints(t)
			case *corev1.Node:
				c.index.addFromNode(t)
			case *batchv1.Job:
				c.index.jobs[t.UID] = t.ObjectMeta
			case *appsv1.ReplicaSet:
				c.index.replicaSets[t.UID] = t.ObjectMeta
			case *appsv1.Deployment:
				c.index.deployments[t.UID] = t
			}

			if kubeObj, ok := obj.(Object); ok {
				c.fireKubernetesAddEvent(kubeObj)
			}
		},
		UpdateFunc: func(oldObj, newObj any) {
			c.mu.Lock()
			defer c.mu.Unlock()

			switch t := newObj.(type) {
			case *corev1.Pod:
				c.index.addFromPod(t)
			case *corev1.Service:
				c.index.addFromService(t)
			case *corev1.Endpoints:
				c.index.addFromEndpoints(t)
			case *corev1.Node:
				c.index.addFromNode(t)
			case *batchv1.Job:
				c.index.jobs[t.UID] = t.ObjectMeta
			case *appsv1.ReplicaSet:
				c.index.replicaSets[t.UID] = t.ObjectMeta
			case *appsv1.Deployment:
				c.index.deployments[t.UID] = t
			}

			if kubeObj, ok := newObj.(Object); ok {
				c.fireKubernetesUpdateEvent(kubeObj)
			}
		},
		DeleteFunc: func(obj interface{}) {
			c.mu.Lock()
			defer c.mu.Unlock()

			switch t := obj.(type) {
			case *corev1.Pod:
				c.index.deleteFromPod(t)
			case *corev1.Service:
				c.index.deleteFromService(t)
			case *corev1.Endpoints:
				c.index.deleteFromEndpoints(t)
			case *corev1.Node:
				c.index.deleteByNode(t)
			case *batchv1.Job:
				delete(c.index.jobs, t.UID)
			case *appsv1.ReplicaSet:
				delete(c.index.replicaSets, t.UID)
			case *appsv1.Deployment:
				delete(c.index.deployments, t.UID)
			}

			if kubeObj, ok := obj.(Object); ok {
				c.fireKubernetesDeleteEvent(kubeObj)
			}
		},
	}
}

func (c *Client) GetIPInfo(ip netip.Addr) (IPInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	val, found := c.index.ipsDetails[ip]
	return val, found
}

func (c *Client) GetPodInfo(uid string) (*PodInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	podInfo, found := c.index.pods[types.UID(uid)]
	if !found {
		return nil, false
	}
	return podInfo, true
}

func (c *Client) GetOwnerUID(obj Object) string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	switch v := obj.(type) {
	case *corev1.Pod:
		return string(c.index.getPodOwner(v).UID)
	}

	if len(obj.GetOwnerReferences()) == 0 {
		return ""
	}
	return string(obj.GetOwnerReferences()[0].UID)
}

type ClusterInfo struct {
	PodCidr     string
	ServiceCidr string
}

func (c *Client) GetClusterInfo() (*ClusterInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.clusterInfo != nil {
		return c.clusterInfo, nil
	}

	var res ClusterInfo
	// Try to find pods cidr from nodes.
	for _, node := range c.index.nodesByName {
		if node.Spec.PodCIDR != "" {
			subnet, err := netip.ParsePrefix(node.Spec.PodCIDR)
			if err != nil {
				return nil, fmt.Errorf("parse node pod cidr: %w", err)
			}
			res.PodCidr = netip.PrefixFrom(subnet.Addr(), 16).String()
			break
		}
	}

	for _, info := range c.index.ipsDetails {
		// Find service cidr from clusterIP services.
		if svc := info.Service; svc != nil && svc.Spec.Type == corev1.ServiceTypeClusterIP {
			if svc.Spec.ClusterIP != "" && svc.Spec.ClusterIP != corev1.ClusterIPNone {
				addr, err := netip.ParseAddr(svc.Spec.ClusterIP)
				if err != nil {
					return nil, fmt.Errorf("parse service cluster ip: %w", err)
				}
				cidr, err := addr.Prefix(16)
				if err != nil {
					return nil, fmt.Errorf("get cluster ip prefix: %w", err)
				}
				res.ServiceCidr = cidr.String()
				if res.PodCidr != "" {
					break
				}
			}
		}
		// Find pod cidr from pod if not found from nodes.
		if res.PodCidr == "" {
			if pod := info.PodInfo; pod != nil && pod.Pod != nil && pod.Pod.Status.PodIP != "" {
				addr, err := netip.ParseAddr(pod.Pod.Status.PodIP)
				if err != nil {
					return nil, fmt.Errorf("parse pod addr: %w", err)
				}
				cidr, err := addr.Prefix(16)
				if err != nil {
					return nil, fmt.Errorf("get pod ip prefix: %w", err)
				}
				res.PodCidr = cidr.String()
				if res.ServiceCidr != "" {
					break
				}
			}
		}
	}
	if res.PodCidr == "" && res.ServiceCidr == "" {
		return nil, fmt.Errorf("no pod cidr or service cidr found")
	}
	c.clusterInfo = &res
	return &res, nil
}

type ImageDetails struct {
	ScannerImageName string
	ImagePullSecrets []corev1.LocalObjectReference
}

// GetKvisorAgentImageDetails returns kvisor agent image details.
// This is used for image analyzer and kube-bench dynamic jobs to schedule using the same image.
func (c *Client) GetKvisorAgentImageDetails() (ImageDetails, error) {
	spec, err := c.getKvisorControllerPodSpec()
	if err != nil {
		return ImageDetails{}, err
	}

	imageName := os.Getenv("SCANNERS_IMAGE")
	if imageName == "" {
		for _, container := range spec.Containers {
			if container.Name == c.kvisorControllerContainerName {
				imageName = container.Image
				break
			}
		}

		imageName = strings.Replace(imageName, "-controller", "-scanners", 1)
	}

	if imageName == "" {
		return ImageDetails{}, errors.New("kvisor container image not found")
	}

	return ImageDetails{
		ScannerImageName: imageName,
		ImagePullSecrets: spec.ImagePullSecrets,
	}, nil
}

func (c *Client) getKvisorControllerPodSpec() (*corev1.PodSpec, error) {
	c.mu.RLock()
	spec := c.kvisorControllerPodSpec
	c.mu.RUnlock()
	if spec != nil {
		return spec, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pod, err := c.client.CoreV1().Pods(c.kvisorNamespace).Get(ctx, c.podName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.kvisorControllerPodSpec = &pod.Spec
	c.mu.Unlock()

	return &pod.Spec, nil
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

func (c *Client) UnregisterKubernetesChangeListener(l KubernetesChangeEventListener) {
	c.changeListenersMu.Lock()
	defer c.changeListenersMu.Unlock()

	for i, lis := range c.changeListeners {
		if lis.lis == l {
			c.changeListeners = slices.Delete(c.changeListeners, i, i+1)
			return
		}
	}
}

func (c *Client) fireKubernetesAddEvent(obj Object) {
	c.changeListenersMu.RLock()
	listeners := c.changeListeners
	c.changeListenersMu.RUnlock()

	for _, l := range listeners {
		actionListener, ok := l.lis.(AddListener)
		if ok && l.required(obj) {
			go actionListener.OnAdd(obj)
		}
	}
}

func (c *Client) fireKubernetesUpdateEvent(obj Object) {
	c.changeListenersMu.RLock()
	listeners := c.changeListeners
	c.changeListenersMu.RUnlock()

	for _, l := range listeners {
		actionListener, ok := l.lis.(UpdateListener)
		if ok && l.required(obj) {
			go actionListener.OnUpdate(obj)
		}
	}
}

func (c *Client) fireKubernetesDeleteEvent(obj Object) {
	c.changeListenersMu.RLock()
	listeners := c.changeListeners
	c.changeListenersMu.RUnlock()

	for _, l := range listeners {
		actionListener, ok := l.lis.(DeleteListener)
		if ok && l.required(obj) {
			go actionListener.OnDelete(obj)
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
