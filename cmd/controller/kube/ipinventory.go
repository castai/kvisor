package kube

import (
	"sync"

	corev1 "k8s.io/api/core/v1"
)

func NewIPInventory() *IPInventory {
	return &IPInventory{
		items: map[string]IPInfo{},
	}
}

type IPInventory struct {
	mu    sync.RWMutex
	items map[string]IPInfo
}

func (i *IPInventory) Get(ip string) (IPInfo, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	info, found := i.items[ip]
	return info, found
}

func (i *IPInventory) List() []IPInfo {
	i.mu.RLock()
	defer i.mu.RUnlock()
	list := make([]IPInfo, 0, len(i.items))
	for ip, info := range i.items {
		info := info
		info.IP = ip
		list = append(list, info)
	}
	return list
}

func (i *IPInventory) add(v any) {
	i.mu.Lock()
	defer i.mu.Unlock()

	switch t := v.(type) {
	case *Pod:
		i.addFromPod(t)
	case *corev1.Endpoints:
		i.addFromEndpoints(t)
	case *corev1.Service:
		i.addFromService(t)
	case *corev1.Node:
		i.addFromNode(t)
	}
}

func (i *IPInventory) delete(v any) {
	i.mu.Lock()
	defer i.mu.Unlock()

	switch t := v.(type) {
	case *Pod:
		i.deleteFromPod(t)
	case *corev1.Endpoints:
		i.deleteFromEndpoints(t)
	case *corev1.Service:
		i.deleteFromService(t)
	case *corev1.Node:
		i.deleteFromNode(t)
	}
}

func (i *IPInventory) addFromPod(v *Pod) {
	if v.Pod.Spec.HostNetwork {
		return
	}

	i.items[v.Pod.Status.PodIP] = IPInfo{Pod: v}
}

func (i *IPInventory) addFromEndpoints(v *corev1.Endpoints) {
	for _, subset := range v.Subsets {
		for _, address := range subset.Addresses {
			// Skip adding entries if target info exists. Will be added by pods.
			if address.TargetRef != nil {
				continue
			}

			i.items[address.IP] = IPInfo{Endpoint: &IPEndpoint{
				ID:        string(v.UID),
				Name:      v.Name,
				Namespace: v.Namespace,
				Labels:    v.Labels,
			}}
		}
	}
}

func (i *IPInventory) addFromService(v *corev1.Service) {
	ips := getServiceIPs(v)
	if len(ips) == 0 {
		return
	}

	for _, ip := range ips {
		i.items[ip] = IPInfo{Service: v}
	}
}

func (i *IPInventory) addFromNode(v *corev1.Node) {
	for _, address := range v.Status.Addresses {
		if address.Type == corev1.NodeInternalIP {
			i.items[address.Address] = IPInfo{Node: v}
			return
		}
	}
}

func (i *IPInventory) deleteFromPod(v *Pod) {
	if v.Pod.Spec.HostNetwork {
		return
	}

	delete(i.items, v.Pod.Status.PodIP)
}

func (i *IPInventory) deleteFromEndpoints(v *corev1.Endpoints) {
	for _, subset := range v.Subsets {
		for _, address := range subset.Addresses {
			if address.TargetRef != nil {
				continue
			}

			delete(i.items, address.IP)
		}
	}
}

func (i *IPInventory) deleteFromService(v *corev1.Service) {
	ips := getServiceIPs(v)
	if len(ips) == 0 {
		return
	}

	for _, ip := range ips {
		delete(i.items, ip)
	}
}

func (i *IPInventory) deleteFromNode(v *corev1.Node) {
	for _, address := range v.Status.Addresses {
		if address.Type == corev1.NodeInternalIP {
			delete(i.items, address.Address)
		}
	}
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

type IpInfoSummary struct {
	IP         string
	ObjectName string `json:"objectName,omitempty"`
	ObjectType string `json:"objectType,omitempty"`
	Namespace  string `json:"namespace"`
}

type IPInfo struct {
	IP       string
	Pod      *Pod
	Service  *corev1.Service
	Node     *corev1.Node
	Endpoint *IPEndpoint
}

func (i *IPInfo) GetSummary() IpInfoSummary {
	res := IpInfoSummary{
		IP: i.IP,
	}
	if v := i.Pod; v != nil {
		res.ObjectType = "pod"
		res.ObjectName = v.Pod.Name
		res.Namespace = v.Pod.Namespace
		return res
	}
	if v := i.Service; v != nil {
		res.ObjectType = "service"
		res.ObjectName = v.Name
		res.Namespace = v.Namespace
		return res
	}
	if v := i.Node; v != nil {
		res.ObjectType = "node"
		res.ObjectName = v.Name
		res.Namespace = v.Namespace
		return res
	}
	if v := i.Endpoint; v != nil {
		res.ObjectType = "endpoint"
		res.ObjectName = v.Name
		res.Namespace = v.Namespace
		return res
	}
	res.ObjectType = "unknown"
	return res
}
