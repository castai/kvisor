package kube

import (
	"context"
	"fmt"

	kubepb "github.com/castai/kvisor/api/v1/kube"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func NewServer(client *Client) kubepb.KubeAPIServer {
	return &Server{client: client}
}

type Server struct {
	client *Client
}

func (s *Server) GetIPInfo(ctx context.Context, req *kubepb.GetIPInfoRequest) (*kubepb.GetIPInfoResponse, error) {
	info, found := s.client.GetIPInfo(req.Ip)
	if !found {
		return nil, status.Errorf(codes.NotFound, fmt.Sprintf("pod by ip %s not found", req.Ip))
	}
	res := &kubepb.IPInfo{}
	if owner := info.Owner; owner != nil {
		res.WorkloadName = owner.Name
		res.WorkloadKind = owner.Kind
	}
	if info.Node != nil {
		if zone, found := info.Node.Labels["topology.kubernetes.io/zone"]; found {
			res.Zone = zone
		}
		if info.Pod == nil {
			res.WorkloadKind = "Node"
			res.WorkloadName = info.Node.Name
		}
	}
	if pod := info.Pod; pod != nil {
		res.PodUid = string(pod.UID)
		res.PodName = pod.Name
		res.Namespace = pod.Namespace
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
	info, found := s.client.GetClusterInfo()
	if !found {
		return nil, status.Errorf(codes.NotFound, "cluster info found")
	}
	return &kubepb.GetClusterInfoResponse{
		PodsCidr:    info.PodCidr,
		ServiceCidr: info.ServiceCidr,
	}, nil
}

func (s *Server) GetPod(ctx context.Context, req *kubepb.GetPodRequest) (*kubepb.GetPodResponse, error) {
	owner, found := s.client.GetPodOwner(req.Uid)
	if !found {
		return nil, status.Errorf(codes.NotFound, "pod owner found")
	}
	return &kubepb.GetPodResponse{
		Pod: &kubepb.Pod{
			WorkloadName: owner.Name,
			WorkloadKind: owner.Kind,
		},
	}, nil
}
