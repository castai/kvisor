package kube

import (
	"net/netip"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
)

func NewIndex() *Index {
	return &Index{
		ipsDetails:  make(ipsDetails),
		replicaSets: make(map[types.UID]metav1.ObjectMeta),
		jobs:        make(map[types.UID]metav1.ObjectMeta),
		deployments: make(map[types.UID]*appsv1.Deployment),
		pods:        make(map[types.UID]*PodInfo),
		nodesByName: make(map[string]*corev1.Node),
	}
}

type Index struct {
	ipsDetails  ipsDetails
	replicaSets map[types.UID]metav1.ObjectMeta
	jobs        map[types.UID]metav1.ObjectMeta
	deployments map[types.UID]*appsv1.Deployment
	pods        map[types.UID]*PodInfo
	nodesByName map[string]*corev1.Node
}

func (i *Index) addFromPod(pod *corev1.Pod) {
	owner := i.getPodOwner(pod)
	node := i.nodesByName[pod.Spec.NodeName]
	zone := getZone(node)
	podInfo := &PodInfo{
		Pod:   pod,
		Owner: owner,
		Zone:  zone,
	}
	i.pods[pod.UID] = podInfo
	if !pod.Spec.HostNetwork {
		// If dual-stack is enabled we need to parse all pod IPs
		podIPs := pod.Status.PodIPs
		if len(podIPs) == 0 && pod.Status.PodIP != "" {
			podIPs = []corev1.PodIP{{IP: pod.Status.PodIP}}
		}
		for _, p := range podIPs {
			if addr, err := netip.ParseAddr(p.IP); err == nil {
				i.ipsDetails.set(addr, IPInfo{
					PodInfo:    podInfo,
					resourceID: pod.UID,
				})
			}
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
			i.ipsDetails.set(addr, IPInfo{
				Endpoint: &IPEndpoint{
					ID:        string(v.UID),
					Name:      v.Name,
					Namespace: v.Namespace,
					Labels:    v.Labels,
				},
				resourceID: v.UID,
			})
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
		i.ipsDetails.set(addr, IPInfo{
			Service:    v,
			resourceID: v.UID,
		})
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
			i.ipsDetails.set(addr, IPInfo{
				Node:       v,
				resourceID: v.UID,
			})
			return
		}
	}
}

func (i *Index) deleteFromPod(v *corev1.Pod) {
	delete(i.pods, v.UID)

	if !v.Spec.HostNetwork {
		// If dual-stack is enabled we need to delete all pod IPs
		podIPs := v.Status.PodIPs
		if len(podIPs) == 0 && v.Status.PodIP != "" {
			podIPs = []corev1.PodIP{{IP: v.Status.PodIP}}
		}
		for _, p := range podIPs {
			if addr, err := netip.ParseAddr(p.IP); err == nil {
				i.ipsDetails.delete(addr, v.UID)
			}
		}
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
			i.ipsDetails.delete(addr, v.UID)
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
		i.ipsDetails.delete(addr, v.UID)
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
			i.ipsDetails.delete(addr, v.UID)
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
			rsOwner := findOwner(owner, rs.OwnerReferences)
			if rsOwner.Kind == "Deployment" {
				return rsOwner
			}

			if dep, found := findDeploymentByPodSelector(i.deployments, pod); found {
				return metav1.OwnerReference{
					Kind: dep.Kind,
					Name: dep.Name,
					UID:  dep.UID,
				}
			}

			return owner
		}
	case "Job":
		if rs, found := i.jobs[owner.UID]; found {
			jobOwner := findOwner(owner, rs.OwnerReferences)
			if jobOwner.Kind == "CronJob" {
				return jobOwner
			}
			return owner
		}
	case "DaemonSet", "StatefulSet":
		return owner
	}
	// If the pod is managed by a custom CRD, we fall back to just report pod,
	// as we do not handle custom CRDs.
	return metav1.OwnerReference{
		Kind: "Pod",
		Name: pod.Name,
		UID:  pod.UID,
	}
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
		clusterIPs := svc.Spec.ClusterIPs
		if len(clusterIPs) == 0 && svc.Spec.ClusterIP != corev1.ClusterIPNone && svc.Spec.ClusterIP != "" {
			clusterIPs = []string{svc.Spec.ClusterIP}
		}
		return clusterIPs
	case corev1.ServiceTypeLoadBalancer:
		for _, ingress := range svc.Status.LoadBalancer.Ingress {
			if ip := ingress.IP; ip != "" {
				return []string{ip}
			}
		}
	}
	return svc.Spec.ExternalIPs
}

func getZone(n *corev1.Node) string {
	if n == nil {
		return ""
	}
	zone := n.Labels["topology.kubernetes.io/zone"]
	return zone
}

type IPEndpoint struct {
	ID        string
	Name      string
	Namespace string
	Labels    map[string]string
}

type IPInfo struct {
	PodInfo  *PodInfo
	Service  *corev1.Service
	Node     *corev1.Node
	Endpoint *IPEndpoint

	ip         netip.Addr
	resourceID types.UID
	setAt      time.Time
	deleteAt   *time.Time
}

type PodInfo struct {
	Pod   *corev1.Pod
	Owner metav1.OwnerReference
	Zone  string
}
