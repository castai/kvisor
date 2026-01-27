package pipeline

import (
	"context"
	"net/netip"
	"testing"

	kubepb "github.com/castai/kvisor/api/v1/kube"
	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/config"
	"github.com/castai/kvisor/pkg/ebpftracer"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
)

func TestToNetflowDestination(t *testing.T) {
	tests := []struct {
		name         string
		key          ebpftracer.TrafficKey
		summary      ebpftracer.TrafficSummary
		dnsCache     map[netip.Addr]string
		clusterInfo  *clusterInfo
		expectedAddr string
		expectedPort uint32
		expectedDNS  string
		expectedKind string
		expectError  bool
	}{
		{
			name: "public IP - internet flow",
			key: ebpftracer.TrafficKey{
				Tuple: struct {
					Saddr  struct{ Raw [16]uint8 }
					Daddr  struct{ Raw [16]uint8 }
					Sport  uint16
					Dport  uint16
					Family uint16
				}{
					Saddr:  struct{ Raw [16]uint8 }{Raw: [16]byte{0xa, 0, 0, 0xa}},     // 10.0.0.10
					Daddr:  struct{ Raw [16]uint8 }{Raw: [16]byte{0x8, 0x8, 0x8, 0x8}}, // 8.8.8.8 (public)
					Sport:  12345,
					Dport:  443,
					Family: uint16(types.AF_INET),
				},
				Proto: unix.IPPROTO_TCP,
			},
			summary: ebpftracer.TrafficSummary{
				TxBytes:   100,
				TxPackets: 10,
				RxBytes:   200,
				RxPackets: 20,
			},
			expectedAddr: "8.8.8.8",
			expectedPort: 443,
			expectedKind: "internet",
		},
		{
			name: "private IP - private flow",
			key: ebpftracer.TrafficKey{
				Tuple: struct {
					Saddr  struct{ Raw [16]uint8 }
					Daddr  struct{ Raw [16]uint8 }
					Sport  uint16
					Dport  uint16
					Family uint16
				}{
					Saddr:  struct{ Raw [16]uint8 }{Raw: [16]byte{0xa, 0, 0, 0xa}}, // 10.0.0.10
					Daddr:  struct{ Raw [16]uint8 }{Raw: [16]byte{0xa, 0, 0, 0xb}}, // 10.0.0.11 (private)
					Sport:  12345,
					Dport:  80,
					Family: uint16(types.AF_INET),
				},
				Proto: unix.IPPROTO_TCP,
			},
			summary: ebpftracer.TrafficSummary{
				TxBytes:   50,
				TxPackets: 5,
				RxBytes:   100,
				RxPackets: 10,
			},
			expectedAddr: "10.0.0.11",
			expectedPort: 80,
			expectedKind: "private",
		},
		{
			name: "with DNS name",
			key: ebpftracer.TrafficKey{
				Tuple: struct {
					Saddr  struct{ Raw [16]uint8 }
					Daddr  struct{ Raw [16]uint8 }
					Sport  uint16
					Dport  uint16
					Family uint16
				}{
					Saddr:  struct{ Raw [16]uint8 }{Raw: [16]byte{0xa, 0, 0, 0xa}},
					Daddr:  struct{ Raw [16]uint8 }{Raw: [16]byte{0x8, 0x8, 0x8, 0x8}},
					Sport:  12345,
					Dport:  443,
					Family: uint16(types.AF_INET),
				},
				Proto: unix.IPPROTO_TCP,
				ProcessIdentity: struct {
					Pid          uint32
					PidStartTime uint64
					CgroupId     uint64
				}{CgroupId: 100},
			},
			summary: ebpftracer.TrafficSummary{
				TxBytes:   100,
				TxPackets: 10,
				RxBytes:   200,
				RxPackets: 20,
			},
			dnsCache: map[netip.Addr]string{
				netip.MustParseAddr("8.8.8.8"): "dns.google",
			},
			expectedAddr: "8.8.8.8",
			expectedPort: 443,
			expectedDNS:  "dns.google",
			expectedKind: "internet",
		},
		{
			name: "IPv6 public",
			key: ebpftracer.TrafficKey{
				Tuple: struct {
					Saddr  struct{ Raw [16]uint8 }
					Daddr  struct{ Raw [16]uint8 }
					Sport  uint16
					Dport  uint16
					Family uint16
				}{
					Saddr:  struct{ Raw [16]uint8 }{Raw: [16]byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1}},                    // fd00::1 (private)
					Daddr:  struct{ Raw [16]uint8 }{Raw: [16]byte{0x26, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88}}, // 2601:4860:4860::8888 (public)
					Sport:  12345,
					Dport:  53,
					Family: uint16(types.AF_INET6),
				},
				Proto: unix.IPPROTO_UDP,
			},
			summary: ebpftracer.TrafficSummary{
				TxBytes:   64,
				TxPackets: 1,
				RxBytes:   128,
				RxPackets: 1,
			},
			expectedAddr: "2601:4860:4860::8888",
			expectedPort: 53,
			expectedKind: "internet",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := require.New(t)

			ctrl := &Controller{
				cfg: Config{
					Netflow: config.NetflowConfig{
						CheckClusterNetworkRanges: true,
					},
				},
				tracer:      &mockEbpfTracer{dnsCache: tt.dnsCache},
				clusterInfo: tt.clusterInfo,
				ct:          &mockConntrackClient{},
			}

			dest, addr, err := ctrl.toNetflowDestination(tt.key, tt.summary)

			if tt.expectError {
				r.Error(err)
				return
			}

			r.NoError(err)
			r.NotNil(dest)
			r.Equal(tt.expectedAddr, addr.String())
			r.Equal(tt.expectedPort, dest.Port)
			r.Equal(tt.expectedDNS, dest.DnsQuestion)
			r.Equal(tt.expectedKind, dest.WorkloadKind)
			r.Equal(tt.summary.TxBytes, dest.TxBytes)
			r.Equal(tt.summary.TxPackets, dest.TxPackets)
			r.Equal(tt.summary.RxBytes, dest.RxBytes)
			r.Equal(tt.summary.RxPackets, dest.RxPackets)
		})
	}
}

func TestAddNetflowDestination(t *testing.T) {
	tests := []struct {
		name                string
		existingDests       []*castaipb.NetflowDestination
		newDest             *castaipb.NetflowDestination
		destAddr            netip.Addr
		maxPublicIPs        int16
		clusterInfo         *clusterInfo
		expectedDestsCount  int
		expectedMergedIndex int
		checkMergedDest     bool
	}{
		{
			name:          "add first destination",
			existingDests: nil,
			newDest: &castaipb.NetflowDestination{
				Addr:      netip.MustParseAddr("8.8.8.8").AsSlice(),
				Port:      443,
				TxBytes:   100,
				TxPackets: 10,
				RxBytes:   200,
				RxPackets: 20,
			},
			destAddr:           netip.MustParseAddr("8.8.8.8"),
			maxPublicIPs:       10,
			expectedDestsCount: 1,
		},
		{
			name: "add private destination - no merge",
			existingDests: []*castaipb.NetflowDestination{
				{Addr: netip.MustParseAddr("10.0.0.1").AsSlice(), Port: 80},
			},
			newDest: &castaipb.NetflowDestination{
				Addr:      netip.MustParseAddr("10.0.0.2").AsSlice(),
				Port:      80,
				TxBytes:   50,
				TxPackets: 5,
			},
			destAddr:           netip.MustParseAddr("10.0.0.2"),
			maxPublicIPs:       10,
			expectedDestsCount: 2,
		},
		{
			name: "merge internet IPs after threshold",
			existingDests: []*castaipb.NetflowDestination{
				{Addr: netip.MustParseAddr("35.199.192.1").AsSlice(), Port: 443, TxBytes: 100, TxPackets: 10},
			},
			newDest: &castaipb.NetflowDestination{
				Addr:      netip.MustParseAddr("35.199.192.2").AsSlice(),
				Port:      443,
				TxBytes:   200,
				TxPackets: 20,
				RxBytes:   300,
				RxPackets: 30,
			},
			destAddr:            netip.MustParseAddr("35.199.192.2"),
			maxPublicIPs:        1,
			expectedDestsCount:  2, // one existing + one merged 0.0.0.0
			expectedMergedIndex: 1,
			checkMergedDest:     true,
		},
		{
			name: "cloud IP - no merge",
			existingDests: []*castaipb.NetflowDestination{
				{Addr: netip.MustParseAddr("35.199.192.1").AsSlice(), Port: 443},
			},
			newDest: &castaipb.NetflowDestination{
				Addr:      netip.MustParseAddr("35.199.192.2").AsSlice(),
				Port:      443,
				TxBytes:   200,
				TxPackets: 20,
			},
			destAddr: netip.MustParseAddr("35.199.192.2"),
			clusterInfo: &clusterInfo{
				cloudCidr: []netip.Prefix{
					netip.MustParsePrefix("35.199.192.0/19"),
				},
			},
			maxPublicIPs:       1,
			expectedDestsCount: 2, // should not merge because of Cloud IP
		},
		{
			name: "public non-cloud destination - no merge",
			existingDests: []*castaipb.NetflowDestination{
				{Addr: netip.MustParseAddr("8.8.8.8").AsSlice(), Port: 443},
			},
			newDest: &castaipb.NetflowDestination{
				Addr:      netip.MustParseAddr("1.1.1.1").AsSlice(),
				Port:      443,
				TxBytes:   100,
				TxPackets: 10,
			},
			destAddr:           netip.MustParseAddr("1.1.1.1"),
			maxPublicIPs:       1,
			expectedDestsCount: 2, // should not merge non-cloud public destinations
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := require.New(t)

			netflow := &netflowVal{
				pb: &castaipb.Netflow{
					Destinations: tt.existingDests,
				},
			}

			if tt.existingDests != nil && len(tt.existingDests) > 0 {
				netflow.mergeThreshold = len(tt.existingDests)
			}

			ctrl := &Controller{
				cfg: Config{
					Netflow: config.NetflowConfig{
						MaxPublicIPs: tt.maxPublicIPs,
					},
				},
				clusterInfo: tt.clusterInfo,
			}
			if ctrl.clusterInfo == nil {
				ctrl.clusterInfo = &clusterInfo{}
			}

			ctrl.addNetflowDestination(netflow, tt.newDest, tt.destAddr)

			r.Equal(tt.expectedDestsCount, len(netflow.pb.Destinations))

			if tt.checkMergedDest {
				r.Equal(tt.expectedMergedIndex, netflow.mergedDestIndex)
				mergedDest := netflow.pb.Destinations[netflow.mergedDestIndex]
				r.Equal([]byte{0, 0, 0, 0}, mergedDest.Addr)
				r.Equal(tt.newDest.TxBytes, mergedDest.TxBytes)
				r.Equal(tt.newDest.TxPackets, mergedDest.TxPackets)
			}
		})
	}
}

func TestEnrichKubeDestinations(t *testing.T) {
	tests := []struct {
		name             string
		flows            map[uint64]*netflowGroup
		ips              map[netip.Addr]struct{}
		kubeResponse     *kubepb.GetIPsInfoResponse
		expectedPodName  string
		expectedZone     string
		expectedRegion   string
		expectedKind     string
		expectedWorkload string
		expectedDNS      string
	}{
		{
			name: "enrich with pod info",
			flows: map[uint64]*netflowGroup{
				100: {
					flows: map[uint64]*netflowVal{
						1: {
							pb: &castaipb.Netflow{
								Destinations: []*castaipb.NetflowDestination{
									{
										Addr: netip.MustParseAddr("10.0.0.10").AsSlice(),
										Port: 80,
									},
								},
							},
						},
					},
				},
			},
			ips: map[netip.Addr]struct{}{
				netip.MustParseAddr("10.0.0.10"): {},
			},
			kubeResponse: &kubepb.GetIPsInfoResponse{
				List: []*kubepb.IPInfo{
					{
						Ip:           netip.MustParseAddr("10.0.0.10").AsSlice(),
						PodName:      "test-pod",
						Namespace:    "default",
						WorkloadName: "test-deployment",
						WorkloadKind: "Deployment",
						Zone:         "us-east-1a",
						Region:       "us-east-1",
						NodeName:     "node1",
					},
				},
			},
			expectedPodName:  "test-pod",
			expectedZone:     "us-east-1a",
			expectedRegion:   "us-east-1",
			expectedKind:     "Deployment",
			expectedWorkload: "test-deployment",
		},
		{
			name: "enrich with cloud domain",
			flows: map[uint64]*netflowGroup{
				100: {
					flows: map[uint64]*netflowVal{
						1: {
							pb: &castaipb.Netflow{
								Destinations: []*castaipb.NetflowDestination{
									{
										Addr: netip.MustParseAddr("35.199.192.1").AsSlice(),
										Port: 443,
									},
								},
							},
						},
					},
				},
			},
			ips: map[netip.Addr]struct{}{
				netip.MustParseAddr("35.199.192.1"): {},
			},
			kubeResponse: &kubepb.GetIPsInfoResponse{
				List: []*kubepb.IPInfo{
					{
						Ip:          netip.MustParseAddr("35.199.192.1").AsSlice(),
						CloudDomain: "googleapis.com",
						Zone:        "us-east-1a",
						Region:      "us-east-1",
					},
				},
			},
			expectedZone:     "us-east-1a",
			expectedRegion:   "us-east-1",
			expectedKind:     "cloud",
			expectedWorkload: "gcp",
			expectedDNS:      "googleapis.com",
		},
		{
			name: "cloud domain with existing DNS - preserve DNS",
			flows: map[uint64]*netflowGroup{
				100: {
					flows: map[uint64]*netflowVal{
						1: {
							pb: &castaipb.Netflow{
								Destinations: []*castaipb.NetflowDestination{
									{
										Addr:        netip.MustParseAddr("35.199.192.1").AsSlice(),
										Port:        443,
										DnsQuestion: "storage.googleapis.com",
									},
								},
							},
						},
					},
				},
			},
			ips: map[netip.Addr]struct{}{
				netip.MustParseAddr("35.199.192.1"): {},
			},
			kubeResponse: &kubepb.GetIPsInfoResponse{
				List: []*kubepb.IPInfo{
					{
						Ip:          netip.MustParseAddr("35.199.192.1").AsSlice(),
						CloudDomain: "googleapis.com",
					},
				},
			},
			expectedKind:     "cloud",
			expectedWorkload: "gcp",
			expectedDNS:      "storage.googleapis.com", // should preserve existing DNS
		},
		{
			name: "no matching IP info",
			flows: map[uint64]*netflowGroup{
				100: {
					flows: map[uint64]*netflowVal{
						1: {
							pb: &castaipb.Netflow{
								Destinations: []*castaipb.NetflowDestination{
									{
										Addr: netip.MustParseAddr("10.0.0.10").AsSlice(),
										Port: 80,
									},
								},
							},
						},
					},
				},
			},
			ips: map[netip.Addr]struct{}{
				netip.MustParseAddr("10.0.0.10"): {},
			},
			kubeResponse: &kubepb.GetIPsInfoResponse{
				List: []*kubepb.IPInfo{},
			},
			expectedPodName: "", // should remain empty
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := require.New(t)

			ctrl := &Controller{
				kubeClient: &mockKubeClientWithResponse{
					response: tt.kubeResponse,
				},
			}

			ctrl.enrichKubeDestinations(context.Background(), tt.flows, tt.ips)

			// Get the first destination from the first flow
			var dest *castaipb.NetflowDestination
			for _, group := range tt.flows {
				for _, flow := range group.flows {
					if len(flow.pb.Destinations) > 0 {
						dest = flow.pb.Destinations[0]
						break
					}
				}
			}

			r.NotNil(dest)
			r.Equal(tt.expectedPodName, dest.PodName)
			r.Equal(tt.expectedZone, dest.Zone)
			r.Equal(tt.expectedRegion, dest.Region)
			r.Equal(tt.expectedKind, dest.WorkloadKind)
			r.Equal(tt.expectedWorkload, dest.WorkloadName)
			if tt.expectedDNS != "" {
				r.Equal(tt.expectedDNS, dest.DnsQuestion)
			}
		})
	}
}

// mockKubeClientWithResponse is a mock that returns a specific response
type mockKubeClientWithResponse struct {
	response *kubepb.GetIPsInfoResponse
}

func (m *mockKubeClientWithResponse) GetIPsInfo(ctx context.Context, in *kubepb.GetIPsInfoRequest, opts ...grpc.CallOption) (*kubepb.GetIPsInfoResponse, error) {
	return m.response, nil
}

func (m *mockKubeClientWithResponse) GetClusterInfo(ctx context.Context, in *kubepb.GetClusterInfoRequest, opts ...grpc.CallOption) (*kubepb.GetClusterInfoResponse, error) {
	return &kubepb.GetClusterInfoResponse{}, nil
}

func (m *mockKubeClientWithResponse) GetIPInfo(ctx context.Context, in *kubepb.GetIPInfoRequest, opts ...grpc.CallOption) (*kubepb.GetIPInfoResponse, error) {
	return nil, nil
}

func (m *mockKubeClientWithResponse) GetPod(ctx context.Context, in *kubepb.GetPodRequest, opts ...grpc.CallOption) (*kubepb.GetPodResponse, error) {
	return &kubepb.GetPodResponse{Pod: &kubepb.Pod{}}, nil
}

func (m *mockKubeClientWithResponse) GetPodVolumes(ctx context.Context, in *kubepb.GetPodVolumesRequest, opts ...grpc.CallOption) (*kubepb.GetPodVolumesResponse, error) {
	return &kubepb.GetPodVolumesResponse{}, nil
}

func (m *mockKubeClientWithResponse) GetCloudVolumes(ctx context.Context, in *kubepb.GetCloudVolumesRequest, opts ...grpc.CallOption) (*kubepb.GetCloudVolumesResponse, error) {
	return &kubepb.GetCloudVolumesResponse{}, nil
}

func (m *mockKubeClientWithResponse) GetNode(ctx context.Context, req *kubepb.GetNodeRequest, opts ...grpc.CallOption) (*kubepb.GetNodeResponse, error) {
	return &kubepb.GetNodeResponse{Node: &kubepb.Node{Labels: make(map[string]string)}}, nil
}

func (m *mockKubeClientWithResponse) GetNodeStatsSummary(ctx context.Context, req *kubepb.GetNodeStatsSummaryRequest, opts ...grpc.CallOption) (*kubepb.GetNodeStatsSummaryResponse, error) {
	return &kubepb.GetNodeStatsSummaryResponse{Node: &kubepb.NodeStats{NodeName: req.NodeName}}, nil
}
