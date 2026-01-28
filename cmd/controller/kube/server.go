package kube

import (
	"context"
	"net/netip"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"

	_ "google.golang.org/grpc/encoding/gzip"

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
		res.NodeName = info.Node.GetName()
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

func (s *Server) GetIPsInfo(ctx context.Context, req *kubepb.GetIPsInfoRequest) (*kubepb.GetIPsInfoResponse, error) {
	ips := make([]netip.Addr, 0, len(req.Ips))
	for _, rawIP := range req.Ips {
		ip, ok := netip.AddrFromSlice(rawIP)
		if !ok {
			return nil, status.Errorf(codes.InvalidArgument, "invalid ip: %v", string(rawIP))
		}
		ips = append(ips, ip)
	}

	res := &kubepb.GetIPsInfoResponse{
		List: make([]*kubepb.IPInfo, 0, len(ips)),
	}
	for _, ip := range ips {
		pbInfo := &kubepb.IPInfo{
			Ip: ip.AsSlice(),
		}

		info, ok := s.client.GetIPInfo(ip)
		if ok {
			pbInfo.Zone = info.zone
			pbInfo.Region = info.region
			pbInfo.CloudDomain = info.cloudDomain

			if info.Node != nil {
				pbInfo.Zone = getZone(info.Node)
				pbInfo.Region = getRegion(info.Node)
				pbInfo.NodeName = info.Node.GetName()
			}
			if podInfo := info.PodInfo; podInfo != nil {
				pbInfo.PodUid = string(podInfo.Pod.UID)
				pbInfo.PodName = podInfo.Pod.Name
				pbInfo.Namespace = podInfo.Pod.Namespace
				pbInfo.WorkloadUid = string(podInfo.Owner.UID)
				pbInfo.WorkloadName = podInfo.Owner.Name
				pbInfo.WorkloadKind = podInfo.Owner.Kind
				pbInfo.Zone = podInfo.Zone
				pbInfo.Region = podInfo.Region
				pbInfo.NodeName = podInfo.Pod.Spec.NodeName
			}
			if svc := info.Service; svc != nil {
				pbInfo.WorkloadKind = "Service"
				pbInfo.WorkloadName = svc.Name
				pbInfo.Namespace = svc.Namespace
			}
			if e := info.Endpoint; e != nil {
				pbInfo.WorkloadKind = "Endpoint"
				pbInfo.WorkloadName = e.Name
				pbInfo.Namespace = e.Namespace
			}

			res.List = append(res.List, pbInfo)
		}

	}

	return res, nil
}

func (s *Server) GetClusterInfo(ctx context.Context, req *kubepb.GetClusterInfoRequest) (*kubepb.GetClusterInfoResponse, error) {
	info, err := s.client.GetClusterInfo(ctx)
	if err != nil || info == nil {
		return nil, status.Errorf(codes.NotFound, "cluster info not found: %v", err)
	}
	var otherCidr []string
	if !req.ExcludeOtherCidr {
		otherCidr = s.client.vpcIndex.CloudServiceCIDRs()
	}
	return &kubepb.GetClusterInfoResponse{
		PodsCidr:    info.PodCidr,
		ServiceCidr: info.ServiceCidr,
		NodeCidr:    info.NodeCidr,
		OtherCidr:   otherCidr,
		VpcCidr:     s.client.vpcIndex.VpcCIDRs(),
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
			Region:       info.Region,
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

func (s *Server) GetNodeStatsSummary(ctx context.Context, req *kubepb.GetNodeStatsSummaryRequest) (*kubepb.GetNodeStatsSummaryResponse, error) {
	if req.NodeName == "" {
		return nil, status.Errorf(codes.InvalidArgument, "node_name is required")
	}

	resp, err := s.client.GetNodeStatsSummary(ctx, req.NodeName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get node stats summary: %v", err)
	}

	return resp, nil
}

func (s *Server) GetPodVolumes(ctx context.Context, req *kubepb.GetPodVolumesRequest) (*kubepb.GetPodVolumesResponse, error) {
	if req.NodeName == "" {
		return nil, status.Errorf(codes.InvalidArgument, "node_name is required")
	}

	log := s.client.log.WithField("endpoint", "get_pod_volumes")

	pods := s.client.GetPodsOnNode(req.NodeName)
	log.Debugf("found %d pods on node %s", len(pods), req.NodeName)
	var volumes []*kubepb.PodVolumeInfo

	for _, podInfo := range pods {
		pod := podInfo.Pod
		if pod == nil {
			continue
		}

		// Skip kube-system namespace - system pods don't have user-relevant PVCs
		if pod.Namespace == "kube-system" {
			continue
		}

		// Build a map of volume name -> volume for quick lookup
		volumeMap := make(map[string]corev1.Volume)
		for _, vol := range pod.Spec.Volumes {
			volumeMap[vol.Name] = vol
		}

		// Iterate through containers and their volume mounts (filesystem volumes)
		// Only include PVC-backed volumes - skip ephemeral volumes like configMaps, secrets, serviceAccount tokens
		for _, container := range pod.Spec.Containers {
			for _, mount := range container.VolumeMounts {
				vol, exists := volumeMap[mount.Name]
				if !exists {
					continue
				}

				// Only include PVC-backed volumes
				if vol.PersistentVolumeClaim == nil {
					continue
				}

				volInfo := &kubepb.PodVolumeInfo{
					Namespace:      pod.Namespace,
					PodName:        pod.Name,
					PodUid:         string(pod.UID),
					ControllerKind: podInfo.Owner.Kind,
					ControllerName: podInfo.Owner.Name,
					ContainerName:  container.Name,
					VolumeName:     vol.Name,
					MountPath:      mount.MountPath,
					VolumeMode:     "Filesystem",
				}

				s.enrichPVCDetails(volInfo, vol, pod.Namespace)
				volumes = append(volumes, volInfo)
			}

			// Handle block volumes (VolumeDevices)
			for _, device := range container.VolumeDevices {
				vol, exists := volumeMap[device.Name]
				if !exists {
					continue
				}

				// Only include PVC-backed volumes
				if vol.PersistentVolumeClaim == nil {
					continue
				}

				volInfo := &kubepb.PodVolumeInfo{
					Namespace:      pod.Namespace,
					PodName:        pod.Name,
					PodUid:         string(pod.UID),
					ControllerKind: podInfo.Owner.Kind,
					ControllerName: podInfo.Owner.Name,
					ContainerName:  container.Name,
					VolumeName:     vol.Name,
					DevicePath:     device.DevicePath,
					VolumeMode:     "Block",
				}

				s.enrichPVCDetails(volInfo, vol, pod.Namespace)
				volumes = append(volumes, volInfo)
			}
		}
	}

	log.Debugf("returning %d pod volumes for node %s", len(volumes), req.NodeName)
	return &kubepb.GetPodVolumesResponse{
		Volumes: volumes,
	}, nil
}

func (s *Server) GetCloudVolumes(ctx context.Context, req *kubepb.GetCloudVolumesRequest) (*kubepb.GetCloudVolumesResponse, error) {
	if req.NodeName == "" {
		return nil, status.Errorf(codes.InvalidArgument, "node_name is required")
	}

	log := s.client.log.WithField("endpoint", "get_cloud_volumes")

	nodeVolumes := s.client.GetVolumesForNode(req.NodeName)
	if len(nodeVolumes) == 0 {
		return &kubepb.GetCloudVolumesResponse{}, nil
	}

	cloudProvider := s.client.GetCloudProvider()

	volumes := make([]*kubepb.CloudVolumeInfo, 0, len(nodeVolumes))
	for _, vol := range nodeVolumes {
		volInfo := &kubepb.CloudVolumeInfo{
			CloudProvider:   string(cloudProvider),
			Zone:            vol.Zone,
			VolumeId:        vol.VolumeID,
			VolumeType:      vol.VolumeType,
			VolumeState:     vol.VolumeState,
			SizeBytes:       vol.SizeBytes,
			Iops:            vol.IOPS,
			ThroughputBytes: vol.ThroughputBytes,
			Encrypted:       vol.Encrypted,
		}

		volumes = append(volumes, volInfo)
	}

	log.Debugf("returning %d volumes for node %s", len(volumes), req.NodeName)
	return &kubepb.GetCloudVolumesResponse{
		Volumes: volumes,
	}, nil
}

func (s *Server) enrichPVCDetails(volInfo *kubepb.PodVolumeInfo, vol corev1.Volume, namespace string) {
	pvcName := vol.PersistentVolumeClaim.ClaimName
	volInfo.PvcName = pvcName

	pvc, found := s.client.GetPVCByName(namespace, pvcName)
	if !found {
		return
	}

	volInfo.PvcUid = string(pvc.UID)

	// Get requested storage size
	if req, ok := pvc.Spec.Resources.Requests[corev1.ResourceStorage]; ok {
		volInfo.RequestedSizeBytes = req.Value()
	}

	// Get storage class
	if pvc.Spec.StorageClassName != nil {
		volInfo.StorageClass = *pvc.Spec.StorageClassName
	}

	// Get PV details if bound
	if pvc.Spec.VolumeName != "" {
		volInfo.PvName = pvc.Spec.VolumeName

		if pv, found := s.client.GetPVByName(pvc.Spec.VolumeName); found {
			// Get volume source details - supports both CSI and in-tree provisioners
			if pv.Spec.CSI != nil {
				// CSI volume (modern)
				volInfo.CsiDriver = pv.Spec.CSI.Driver
				volInfo.CsiVolumeHandle = extractVolumeID(pv.Spec.CSI.VolumeHandle)
			} else if pv.Spec.AWSElasticBlockStore != nil {
				// In-tree AWS EBS provisioner (gp2 storage class)
				volInfo.CsiDriver = "kubernetes.io/aws-ebs"
				volInfo.CsiVolumeHandle = pv.Spec.AWSElasticBlockStore.VolumeID
			} else if pv.Spec.GCEPersistentDisk != nil {
				// In-tree GCE PD provisioner
				volInfo.CsiDriver = "kubernetes.io/gce-pd"
				volInfo.CsiVolumeHandle = pv.Spec.GCEPersistentDisk.PDName
			} else if pv.Spec.AzureDisk != nil {
				// In-tree Azure Disk provisioner
				volInfo.CsiDriver = "kubernetes.io/azure-disk"
				volInfo.CsiVolumeHandle = pv.Spec.AzureDisk.DiskName
			}
		} else {
			s.client.log.Warnf("PV %s not found in index for PVC %s/%s", pvc.Spec.VolumeName, namespace, pvcName)
		}
	}
}

// extractVolumeID extracts the volume/disk name from a CSI volume handle.
// Different CSI drivers use different path formats:
// - GCP: projects/<project>/zones/<zone>/disks/<disk-name> → <disk-name>
// - AWS: vol-xxx → vol-xxx (no change)
// - Azure: /subscriptions/.../providers/Microsoft.Compute/disks/<disk-name> → <disk-name>
func extractVolumeID(csiVolumeHandle string) string {
	// GCP format: projects/<project>/zones/<zone>/disks/<disk-name>
	if strings.Contains(csiVolumeHandle, "/disks/") {
		parts := strings.Split(csiVolumeHandle, "/disks/")
		if len(parts) == 2 {
			return parts[1]
		}
	}
	// Azure format: /subscriptions/.../providers/Microsoft.Compute/disks/<disk-name>
	if strings.Contains(csiVolumeHandle, "Microsoft.Compute/disks/") {
		parts := strings.Split(csiVolumeHandle, "Microsoft.Compute/disks/")
		if len(parts) == 2 {
			return parts[1]
		}
	}
	// AWS and others: return as-is
	return csiVolumeHandle
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
