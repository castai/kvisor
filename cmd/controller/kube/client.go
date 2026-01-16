package kube

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"regexp"
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

	index    *Index
	vpcIndex *VPCIndex

	clusterInfo *ClusterInfo

	changeListenersMu sync.RWMutex
	changeListeners   []*eventListener
	version           Version
	ipInfoTTL         time.Duration
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
		// TODO: set default
		vpcIndex:  nil,
		version:   version,
		ipInfoTTL: 30 * time.Second,
	}
}

// SetVPCIndex sets the VPC index for enriching external IPs with VPC metadata.
func (i *Client) SetVPCIndex(vpcIndex *VPCIndex) {
	i.vpcIndex = vpcIndex
}

// GetVPCIndex returns the VPC index if available.
func (i *Client) GetVPCIndex() *VPCIndex {
	return i.vpcIndex
}

func (c *Client) RegisterHandlers(factory informers.SharedInformerFactory) {
	informersList := []cache.SharedInformer{
		factory.Core().V1().Nodes().Informer(),
		factory.Core().V1().Services().Informer(),
		factory.Core().V1().Endpoints().Informer(),
		factory.Core().V1().Namespaces().Informer(),
		factory.Core().V1().PersistentVolumeClaims().Informer(),
		factory.Core().V1().PersistentVolumes().Informer(),
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
	// nolint: staticcheck
	ttlCleanupTicker := time.NewTicker(c.ipInfoTTL)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ttlCleanupTicker.C:
			c.runCleanup()
		}
	}
}

func (c *Client) runCleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	deleted := c.index.ipsDetails.cleanup(c.ipInfoTTL)
	if deleted > 0 {
		c.log.Debugf("ips index cleanup done, removed %d ips", deleted)
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
			case *corev1.PersistentVolumeClaim:
				c.index.addFromPVC(t)
			case *corev1.PersistentVolume:
				c.index.addFromPV(t)
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
			case *corev1.PersistentVolumeClaim:
				c.index.addFromPVC(t)
			case *corev1.PersistentVolume:
				c.index.addFromPV(t)
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
			case *corev1.PersistentVolumeClaim:
				c.index.deleteFromPVC(t)
			case *corev1.PersistentVolume:
				c.index.deleteFromPV(t)
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

	val, found := c.index.ipsDetails.find(ip)
	return val, found
}

func (c *Client) GetIPsInfo(ips []netip.Addr) []IPInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var res []IPInfo
	for _, ip := range ips {
		val, found := c.index.ipsDetails.find(ip)
		if found {
			res = append(res, val)
		}
	}
	return res
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

func (c *Client) GetNodeInfo(name string) (*corev1.Node, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	node, found := c.index.nodesByName[name]
	if !found {
		return nil, false
	}
	return node, true
}

func (c *Client) GetPVCByName(namespace, name string) (*corev1.PersistentVolumeClaim, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.index.GetPVCByName(namespace, name)
}

func (c *Client) GetPVByName(name string) (*corev1.PersistentVolume, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.index.GetPVByName(name)
}

func (c *Client) GetPodsOnNode(nodeName string) []*PodInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.index.GetPodsOnNode(nodeName)
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
	PodCidr     []string
	ServiceCidr []string
}

func (c *Client) GetClusterInfo(ctx context.Context) (*ClusterInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.clusterInfo != nil {
		return c.clusterInfo, nil
	}

	var res ClusterInfo
	// Try to find pods cidr from nodes.
	for _, node := range c.index.nodesByName {
		podCidr, err := getPodCidrFromNodeSpec(node)
		if err != nil {
			return nil, err
		}
		if len(podCidr) > 0 {
			res.PodCidr = podCidr
			break
		}
	}

	// Find pod cidr from pod if not found from nodes
	if len(res.PodCidr) == 0 {
		for _, info := range c.index.ipsDetails {
			if len(info) == 0 {
				continue
			}
			first := info[0]
			if pod := first.PodInfo; pod != nil && pod.Pod != nil {
				podCidr, err := getPodCidrFromPod(pod.Pod)
				if err != nil {
					return nil, err
				}
				if len(podCidr) > 0 {
					res.PodCidr = podCidr
					break
				}
			}
		}
	}

	// Try to find service cidr from Kubernetes API output
	serviceCidr, err := getServiceCidr(ctx, c.client, c.kvisorNamespace, c.index.ipsDetails)
	if err != nil {
		return nil, err
	}
	res.ServiceCidr = serviceCidr

	if len(res.PodCidr) == 0 || len(res.ServiceCidr) == 0 {
		return nil, fmt.Errorf("no pod cidr or service cidr found, pod_cidrs=%d, service_cidrs=%d", len(res.PodCidr), len(res.ServiceCidr))
	}
	c.clusterInfo = &res
	return &res, nil
}

func getPodCidrFromNodeSpec(node *corev1.Node) ([]string, error) {
	nodeCidrs := node.Spec.PodCIDRs
	if len(nodeCidrs) == 0 && node.Spec.PodCIDR != "" {
		nodeCidrs = []string{node.Spec.PodCIDR}
	}
	var podCidrs []string
	for _, cidr := range nodeCidrs {
		subnet, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("parsing pod cidr: %w", err)
		}
		prefix := prefixLength(subnet.Addr())
		podCidrs = append(podCidrs, netip.PrefixFrom(subnet.Addr(), prefix).String())
	}
	return podCidrs, nil
}

func getPodCidrFromPod(pod *corev1.Pod) ([]string, error) {
	var podCidr []string
	podIPs := pod.Status.PodIPs
	if len(podIPs) == 0 && pod.Status.PodIP != "" {
		podIPs = []corev1.PodIP{{IP: pod.Status.PodIP}}
	}
	// If dual-stack is enabled we need to parse all pod IPs
	for _, podIP := range podIPs {
		cidr, err := parseIPToCidr(podIP.IP)
		if err != nil {
			return nil, err
		}
		podCidr = append(podCidr, cidr)
	}
	return podCidr, nil
}

func getServiceCidr(ctx context.Context, client kubernetes.Interface, namespace string, ipDetails ipsDetails) ([]string, error) {
	res, err := getServiceCidrFromServiceCreation(ctx, client, namespace)
	if err == nil {
		return res, nil
	}
	allErrs := []error{err}
	res, err = getServiceCidrFromServicesSpec(ipDetails)
	if err != nil {
		allErrs = append(allErrs, err)
		return nil, errors.Join(allErrs...)
	}
	return res, nil
}

func getServiceCidrFromServiceCreation(ctx context.Context, client kubernetes.Interface, namespace string) ([]string, error) {
	var serviceCidr []string
	ipv4Cidr, err := discoverIPv4ServiceCidr(ctx, client, namespace)
	if err != nil {
		return nil, err
	}
	if ipv4Cidr != nil {
		serviceCidr = append(serviceCidr, ipv4Cidr...)
	}

	ipv6Cidr, err := discoverIPv6ServiceCidr(ctx, client, namespace)
	if err != nil {
		return nil, err
	}
	if ipv6Cidr != nil {
		serviceCidr = append(serviceCidr, ipv6Cidr...)
	}
	return serviceCidr, nil
}

func getServiceCidrFromServicesSpec(ipDetails ipsDetails) ([]string, error) {
	for _, details := range ipDetails {
		if len(details) == 0 {
			continue
		}
		first := details[0]
		if first.Service == nil {
			continue
		}
		clusterIPs := first.Service.Spec.ClusterIPs
		if len(clusterIPs) == 0 {
			continue
		}
		var res []string
		for _, clusterIP := range clusterIPs {
			cidr, err := parseIPToCidr(clusterIP)
			if err != nil {
				return nil, err
			}
			res = append(res, cidr)
		}
		return res, nil
	}
	return nil, errors.New("no service cidr found")
}

func discoverIPv4ServiceCidr(ctx context.Context, client kubernetes.Interface, namespace string) ([]string, error) {
	return discoverServiceCidr(ctx, client, "0.0.0.0", namespace)
}

func discoverIPv6ServiceCidr(ctx context.Context, client kubernetes.Interface, namespace string) ([]string, error) {
	return discoverServiceCidr(ctx, client, "::", namespace)
}

// discoverServiceCidr returns the service CIDR by creating a service with an invalid IP and parsing the
// error message returned by the Kubernetes API. This is required because Kubernetes does not implement an API endpoint
// to retrieve the service CIDR.
//
// This is based on https://github.com/submariner-io/submariner-operator/blob/76120c810452c3488e6d56951bb176b35a29d795/pkg/discovery/network/generic.go#L106
func discoverServiceCidr(ctx context.Context, client kubernetes.Interface, ip, namespace string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	discoveryService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cidr-discovery-svc",
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: ip,
		},
	}

	_, err := client.CoreV1().Services(namespace).Create(ctx, discoveryService, metav1.CreateOptions{})
	if err == nil {
		return nil, fmt.Errorf("discovery service should not be created")
	}

	// The error message contains the service CIDR in the format "The range of valid IPs is 10.45.0.0/16"
	re := regexp.MustCompile(".*valid IPs is (.*)$")
	match := re.FindStringSubmatch(err.Error())
	if len(match) == 0 {
		// do not return error if IPv6 or IPv4 is not configured
		if strings.Contains(err.Error(), "not configured") {
			return nil, nil
		}
		return nil, err
	}
	var servicesCidr []string
	for _, cidr := range strings.Split(match[1], ",") {
		subnet, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("parsing service cidr: %w", err)
		}
		prefix := prefixLength(subnet.Addr())
		servicesCidr = append(servicesCidr, netip.PrefixFrom(subnet.Addr(), prefix).String())
	}
	return servicesCidr, nil
}

func parseIPToCidr(ip string) (string, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return "", fmt.Errorf("parse ip: %w", err)
	}
	prefix := prefixLength(addr)
	cidr, err := addr.Prefix(prefix)
	if err != nil {
		return "", fmt.Errorf("get ip prefix: %w", err)
	}
	return cidr.String(), nil
}

// prefixLength returns the absolute CIDR for IPv4 and IPv6 addresses
func prefixLength(addr netip.Addr) int {
	if addr.Is6() {
		return 48
	}
	return 14
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
