package kube

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/castai/kvisor/pkg/cidrindex"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
)

func NewIndex() *Index {
	nodesCIDRIndex, _ := cidrindex.NewIndex[*corev1.Node](1000, 30*time.Second)
	return &Index{
		ipsDetails:     make(ipsDetails),
		replicaSets:    make(map[types.UID]metav1.ObjectMeta),
		jobs:           make(map[types.UID]metav1.ObjectMeta),
		deployments:    make(map[types.UID]*appsv1.Deployment),
		pods:           make(map[types.UID]*PodInfo),
		nodesByName:    make(map[string]*corev1.Node),
		nodesCIDRIndex: nodesCIDRIndex,
	}
}

type Index struct {
	ipsDetails     ipsDetails
	replicaSets    map[types.UID]metav1.ObjectMeta
	jobs           map[types.UID]metav1.ObjectMeta
	deployments    map[types.UID]*appsv1.Deployment
	pods           map[types.UID]*PodInfo
	nodesByName    map[string]*corev1.Node
	nodesCIDRIndex *cidrindex.Index[*corev1.Node]
}

func (i *Index) addFromPod(pod *corev1.Pod) {
	owner := i.getPodOwner(pod)
	node := i.nodesByName[pod.Spec.NodeName]
	zone := getZone(node)
	region := getRegion(node)
	podInfo := &PodInfo{
		Pod:    pod,
		Owner:  owner,
		Zone:   zone,
		Region: region,
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
					zone:       zone,
					region:     region,
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

	zone := getZone(v)
	region := getRegion(v)

	// Associate pods CIDR with node reference to be able to find pods
	// in cases when multiple pods have the same IP (i.e. hostNetwork: true)
	if podCidrs, err := getPodCidrsFromNodeSpec(v); err == nil {
		fmt.Printf("Add pod cidrs %v to node %v at %v\n", podCidrs, v.GetName(), time.Now())
		for _, cidr := range podCidrs {
			_ = i.nodesCIDRIndex.Add(cidr, v)
		}
	}

	for _, address := range v.Status.Addresses {
		if address.Type == corev1.NodeInternalIP {
			addr, err := netip.ParseAddr(address.Address)
			if err != nil {
				continue
			}
			i.ipsDetails.set(addr, IPInfo{
				Node:       v,
				resourceID: v.UID,
				zone:       zone,
				region:     region,
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

	if podCidrs, err := getPodCidrsFromNodeSpec(v); err == nil {
		fmt.Printf("Remove pod cidrs %v from node %v at %v\n", podCidrs, v.GetName(), time.Now())
		for _, cidr := range podCidrs {
			i.nodesCIDRIndex.MarkDeleted(cidr)
		}
	}

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

func getRegion(n *corev1.Node) string {
	if n == nil {
		return ""
	}
	region := n.Labels["topology.kubernetes.io/region"]
	return region
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

	zone        string
	region      string
	cloudDomain string
	ip          netip.Addr
	resourceID  types.UID
	setAt       time.Time
	deleteAt    *time.Time
}

// String returns a debug-friendly representation of IPInfo.
func (info IPInfo) String() string {
	var parts []string

	if info.ip.IsValid() {
		parts = append(parts, fmt.Sprintf("ip=%s", info.ip))
	}

	if info.zone != "" {
		parts = append(parts, fmt.Sprintf("zone=%s", info.zone))
	}
	if info.region != "" {
		parts = append(parts, fmt.Sprintf("region=%s", info.region))
	}
	if info.cloudDomain != "" {
		parts = append(parts, fmt.Sprintf("cloudDomain=%s", info.cloudDomain))
	}

	if info.Node != nil {
		nodeName := info.Node.GetName()
		var nodeIP string
		for _, addr := range info.Node.Status.Addresses {
			if addr.Type == corev1.NodeInternalIP {
				nodeIP = addr.Address
				break
			}
		}
		if nodeIP != "" {
			parts = append(parts, fmt.Sprintf("node=%s(%s)", nodeName, nodeIP))
		} else {
			parts = append(parts, fmt.Sprintf("node=%s", nodeName))
		}
	}

	if info.PodInfo != nil {
		podName := fmt.Sprintf("%s/%s", info.PodInfo.Pod.Namespace, info.PodInfo.Pod.Name)
		parts = append(parts, fmt.Sprintf("pod=%s", podName))
		if info.PodInfo.Owner.Name != "" {
			parts = append(parts, fmt.Sprintf("owner=%s/%s", info.PodInfo.Owner.Kind, info.PodInfo.Owner.Name))
		}
	}

	if info.Service != nil {
		svcName := fmt.Sprintf("%s/%s", info.Service.Namespace, info.Service.Name)
		parts = append(parts, fmt.Sprintf("service=%s", svcName))
		if info.Service.Spec.ClusterIP != "" {
			parts = append(parts, fmt.Sprintf("clusterIP=%s", info.Service.Spec.ClusterIP))
		}
	}

	if info.Endpoint != nil {
		epName := fmt.Sprintf("%s/%s", info.Endpoint.Namespace, info.Endpoint.Name)
		parts = append(parts, fmt.Sprintf("endpoint=%s", epName))
	}

	if info.resourceID != "" {
		parts = append(parts, fmt.Sprintf("resourceID=%s", info.resourceID))
	}
	if !info.setAt.IsZero() {
		parts = append(parts, fmt.Sprintf("setAt=%s", info.setAt.Format(time.RFC3339)))
	}
	if info.deleteAt != nil {
		parts = append(parts, fmt.Sprintf("deleteAt=%s", info.deleteAt.Format(time.RFC3339)))
	}

	if len(parts) == 0 {
		return "IPInfo{empty}"
	}

	return fmt.Sprintf("IPInfo{%s}", strings.Join(parts, " "))
}

type PodInfo struct {
	Pod    *corev1.Pod
	Owner  metav1.OwnerReference
	Zone   string
	Region string
}
