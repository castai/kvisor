package kube

import (
	"context"
	"net/netip"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	kubepb "github.com/castai/kvisor/api/v1/kube"
)

func NewServer(client *Client) kubepb.KubeAPIServer {
	return &Server{client: client}
}

type Server struct {
	client *Client
}

func (s *Server) GetIPInfo(ctx context.Context, req *kubepb.GetIPInfoRequest) (*kubepb.GetIPInfoResponse, error) {
	addr, ok := netip.AddrFromSlice(req.Ip)
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "invalid ip: %v", string(req.Ip))

	}
	info, found := s.client.GetIPInfo(addr)
	if !found {
		return nil, status.Errorf(codes.NotFound, "pod by ip %s not found", addr)
	}
	res := &kubepb.IPInfo{}
	if info.Node != nil {
		res.Zone = getZone(info.Node)
	}
	if podInfo := info.PodInfo; podInfo != nil {
		res.PodUid = string(podInfo.Pod.UID)
		res.PodName = podInfo.Pod.Name
		res.Namespace = podInfo.Pod.Namespace
		res.WorkloadUid = string(podInfo.Owner.UID)
		res.WorkloadName = podInfo.Owner.Name
		res.WorkloadKind = podInfo.Owner.Kind
		res.Zone = podInfo.Zone
		res.NodeName = podInfo.Pod.Spec.NodeName
	}
	if svc := info.Service; svc != nil {
		res.WorkloadKind = "Service"
		res.WorkloadName = svc.Name
		res.Namespace = svc.Namespace
	}
	if e := info.Endpoint; e != nil {
		res.WorkloadKind = "Endpoint"
		res.WorkloadName = e.Name
		res.Namespace = e.Namespace
	}

	return &kubepb.GetIPInfoResponse{
		Info: res,
	}, nil
}

func (s *Server) GetClusterInfo(ctx context.Context, req *kubepb.GetClusterInfoRequest) (*kubepb.GetClusterInfoResponse, error) {
	info, err := s.client.GetClusterInfo(ctx)
	if err != nil || info == nil {
		return nil, status.Errorf(codes.NotFound, "cluster info not found: %v", err)
	}
	return &kubepb.GetClusterInfoResponse{
		PodsCidr:    info.PodCidr,
		ServiceCidr: info.ServiceCidr,
	}, nil
}

func (s *Server) GetPod(ctx context.Context, req *kubepb.GetPodRequest) (*kubepb.GetPodResponse, error) {
	info, found := s.client.GetPodInfo(req.Uid)
	if !found {
		return nil, status.Errorf(codes.NotFound, "pod info not found")
	}
	return &kubepb.GetPodResponse{
		Pod: &kubepb.Pod{
			WorkloadUid:  string(info.Owner.UID),
			WorkloadName: info.Owner.Name,
			WorkloadKind: toProtoWorkloadKind(info.Owner.Kind),
			Zone:         info.Zone,
			NodeName:     info.Pod.Spec.NodeName,
		},
	}, nil
}

func (s *Server) GetNode(ctx context.Context, req *kubepb.GetNodeRequest) (*kubepb.GetNodeResponse, error) {
	node, found := s.client.GetNodeInfo(req.Name)
	if !found {
		return nil, status.Errorf(codes.NotFound, "node info not found")
	}
	return &kubepb.GetNodeResponse{
		Node: &kubepb.Node{
			Name:   node.Name,
			Labels: node.Labels,
		},
	}, nil
}

func toProtoWorkloadKind(kind string) kubepb.WorkloadKind {
	switch kind {
	case "Deployment":
		return kubepb.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT
	case "ReplicaSet":
		return kubepb.WorkloadKind_WORKLOAD_KIND_REPLICA_SET
	case "DaemonSet":
		return kubepb.WorkloadKind_WORKLOAD_KIND_DAEMON_SET
	case "StatefulSet":
		return kubepb.WorkloadKind_WORKLOAD_KIND_STATEFUL_SET
	case "Job":
		return kubepb.WorkloadKind_WORKLOAD_KIND_JOB
	case "CronJob":
		return kubepb.WorkloadKind_WORKLOAD_KIND_CRONJOB
	case "Pod":
		return kubepb.WorkloadKind_WORKLOAD_KIND_POD
	}
	return kubepb.WorkloadKind_WORKLOAD_KIND_UNKNOWN
}
