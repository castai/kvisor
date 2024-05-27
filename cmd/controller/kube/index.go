package kube

import (
	"net/netip"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
)

func NewIndex() *Index {
	return &Index{
		podsInfoByIP: make(map[netip.Addr]IPInfo),
		replicaSets:  make(map[types.UID]metav1.ObjectMeta),
		jobs:         make(map[types.UID]metav1.ObjectMeta),
		deployments:  make(map[types.UID]*appsv1.Deployment),
		pods:         make(map[types.UID]*corev1.Pod),
		nodesByName:  make(map[string]*corev1.Node),
	}
}

type Index struct {
	podsInfoByIP map[netip.Addr]IPInfo
	replicaSets  map[types.UID]metav1.ObjectMeta
	jobs         map[types.UID]metav1.ObjectMeta
	deployments  map[types.UID]*appsv1.Deployment
	pods         map[types.UID]*corev1.Pod
	nodesByName  map[string]*corev1.Node
}

func (i *Index) addFromPod(pod *corev1.Pod) {
	i.pods[pod.UID] = pod
	if !pod.Spec.HostNetwork {
		ipInfo := IPInfo{
			Pod:  pod,
			Node: i.nodesByName[pod.Spec.NodeName],
		}
		owner := i.getPodOwner(pod)
		if owner.UID != pod.UID {
			ipInfo.Owner = &owner
		}
		if addr, err := netip.ParseAddr(pod.Status.PodIP); err == nil {
			i.podsInfoByIP[addr] = ipInfo
		}
	}
}

func (i *Index) addFromEndpoints(v *corev1.Endpoints) {
	for _, subset := range v.Subsets {
		for _, address := range subset.Addresses {
			// Skip adding entries if target info exists. Will be added by pods.
			if address.TargetRef != nil {
				continue
			}

			addr, err := netip.ParseAddr(address.IP)
			if err != nil {
				continue
			}
			i.podsInfoByIP[addr] = IPInfo{Endpoint: &IPEndpoint{
				ID:        string(v.UID),
				Name:      v.Name,
				Namespace: v.Namespace,
				Labels:    v.Labels,
			}}
		}
	}
}

func (i *Index) addFromService(v *corev1.Service) {
	ips := getServiceIPs(v)
	if len(ips) == 0 {
		return
	}

	for _, ip := range ips {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			continue
		}
		i.podsInfoByIP[addr] = IPInfo{Service: v}
	}
}

func (i *Index) addFromNode(v *corev1.Node) {
	i.nodesByName[v.Name] = v

	for _, address := range v.Status.Addresses {
		if address.Type == corev1.NodeInternalIP {
			addr, err := netip.ParseAddr(address.Address)
			if err != nil {
				continue
			}
			i.podsInfoByIP[addr] = IPInfo{Node: v}
			return
		}
	}
}

func (i *Index) deleteFromPod(v *corev1.Pod) {
	delete(i.pods, v.UID)

	if !v.Spec.HostNetwork {
		addr, err := netip.ParseAddr(v.Status.PodIP)
		if err != nil {
			return
		}
		delete(i.podsInfoByIP, addr)
	}
}

func (i *Index) deleteFromEndpoints(v *corev1.Endpoints) {
	for _, subset := range v.Subsets {
		for _, address := range subset.Addresses {
			if address.TargetRef != nil {
				continue
			}
			addr, err := netip.ParseAddr(address.IP)
			if err != nil {
				continue
			}
			delete(i.podsInfoByIP, addr)
		}
	}
}

func (i *Index) deleteFromService(v *corev1.Service) {
	ips := getServiceIPs(v)
	if len(ips) == 0 {
		return
	}

	for _, ip := range ips {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			continue
		}
		delete(i.podsInfoByIP, addr)
	}
}

func (i *Index) deleteByNode(v *corev1.Node) {
	delete(i.nodesByName, v.Name)

	for _, address := range v.Status.Addresses {
		if address.Type == corev1.NodeInternalIP {
			addr, err := netip.ParseAddr(address.Address)
			if err != nil {
				continue
			}
			delete(i.podsInfoByIP, addr)
		}
	}
}

func (i *Index) getPodOwner(pod *corev1.Pod) metav1.OwnerReference {
	if len(pod.OwnerReferences) == 0 {
		return metav1.OwnerReference{
			Kind: "Pod",
			Name: pod.Name,
			UID:  pod.UID,
		}
	}
	owner := pod.OwnerReferences[0]
	switch owner.Kind {
	case "ReplicaSet":
		if rs, found := i.replicaSets[owner.UID]; found {
			owner = findOwner(owner, rs.OwnerReferences)
			if owner.Kind != "Deployment" {
				if dep, found := findDeploymentByPodSelector(i.deployments, pod); found {
					return metav1.OwnerReference{
						Kind: dep.Kind,
						Name: dep.Name,
						UID:  dep.UID,
					}
				}
			}
			return owner
		}
	case "Job":
		if rs, found := i.jobs[owner.UID]; found {
			return findOwner(owner, rs.OwnerReferences)
		}
	}
	return owner
}

func findDeploymentByPodSelector(deployments map[types.UID]*appsv1.Deployment, pod *corev1.Pod) (*appsv1.Deployment, bool) {
	for _, w := range deployments {
		sel, err := metav1.LabelSelectorAsSelector(w.Spec.Selector)
		if err != nil {
			continue
		}
		if sel.Matches(labels.Set(pod.Labels)) {
			return w, true
		}
	}
	return nil, false
}

func findOwner(ref metav1.OwnerReference, refs []metav1.OwnerReference) metav1.OwnerReference {
	if len(refs) > 0 {
		return refs[0]
	}
	return ref
}

func getServiceIPs(svc *corev1.Service) []string {
	switch svc.Spec.Type { //nolint:exhaustive
	case corev1.ServiceTypeClusterIP, corev1.ServiceTypeNodePort:
		if svc.Spec.ClusterIP == corev1.ClusterIPNone {
			return nil
		}
		return []string{svc.Spec.ClusterIP}
	case corev1.ServiceTypeLoadBalancer:
		for _, ingress := range svc.Status.LoadBalancer.Ingress {
			if ip := ingress.IP; ip != "" {
				return []string{ip}
			}
		}
	}
	return svc.Spec.ExternalIPs
}

type IPEndpoint struct {
	ID        string
	Name      string
	Namespace string
	Labels    map[string]string
}

type IPInfo struct {
	IP       string
	Pod      *corev1.Pod
	Service  *corev1.Service
	Node     *corev1.Node
	Endpoint *IPEndpoint
	Owner    *metav1.OwnerReference
}
