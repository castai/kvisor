package pipeline

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	kubepb "github.com/castai/kvisor/api/v1/kube"
	"github.com/castai/logging"
)

func TestNewClusterInfo(t *testing.T) {
	r := require.New(t)
	log := logging.New()
	mockClient := &mockKubeClient{}

	info := newClusterInfo(mockClient, log)

	r.NotNil(info)
	r.Equal(mockClient, info.kubeClient)
	r.Equal(log, info.log)
	r.Empty(info.podCidr)
	r.Empty(info.serviceCidr)
	r.Empty(info.nodeCidr)
	r.Empty(info.vpcCidr)
	r.Empty(info.cloudCidr)
	r.Empty(info.clusterCidr)
}

func TestClusterInfoSync(t *testing.T) {
	tests := []struct {
		name                string
		response            *kubepb.GetClusterInfoResponse
		responseErr         error
		expectedPodCidr     []string
		expectedServiceCidr []string
		expectedNodeCidr    []string
		expectedVpcCidr     []string
		expectedCloudCidr   []string
		expectError         bool
	}{
		{
			name: "successful sync with all CIDRs",
			response: &kubepb.GetClusterInfoResponse{
				PodsCidr:    []string{"10.0.0.0/16", "10.4.0.0/16"},
				ServiceCidr: []string{"10.1.0.0/16", "10.5.0.0/16"},
				NodeCidr:    []string{"10.2.0.0/16"},
				VpcCidr:     []string{"10.3.0.0/16"},
				OtherCidr:   []string{"35.199.192.0/19", "52.0.0.0/8"},
			},
			expectedPodCidr:     []string{"10.0.0.0/16", "10.4.0.0/16"},
			expectedServiceCidr: []string{"10.1.0.0/16", "10.5.0.0/16"},
			expectedNodeCidr:    []string{"10.2.0.0/16"},
			expectedVpcCidr:     []string{"10.3.0.0/16"},
			expectedCloudCidr:   []string{"35.199.192.0/19", "52.0.0.0/8"},
		},
		{
			name: "empty response",
			response: &kubepb.GetClusterInfoResponse{
				PodsCidr:    []string{},
				ServiceCidr: []string{},
			},
			expectedPodCidr:     []string{},
			expectedServiceCidr: []string{},
			expectedNodeCidr:    []string{},
			expectedVpcCidr:     []string{},
			expectedCloudCidr:   []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := require.New(t)
			log := logging.New()

			mockClient := &mockKubeClientWithRetry{
				response: tt.response,
				err:      tt.responseErr,
			}

			info := newClusterInfo(mockClient, log)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			err := info.sync(ctx)

			if tt.expectError {
				r.Error(err)
				return
			}

			r.NoError(err)

			info.mu.RLock()
			r.Len(info.podCidr, len(tt.expectedPodCidr))
			for i, expected := range tt.expectedPodCidr {
				r.Equal(expected, info.podCidr[i].String())
			}

			r.Len(info.serviceCidr, len(tt.expectedServiceCidr))
			for i, expected := range tt.expectedServiceCidr {
				r.Equal(expected, info.serviceCidr[i].String())
			}

			r.Len(info.nodeCidr, len(tt.expectedNodeCidr))
			for i, expected := range tt.expectedNodeCidr {
				r.Equal(expected, info.nodeCidr[i].String())
			}

			r.Len(info.vpcCidr, len(tt.expectedVpcCidr))
			for i, expected := range tt.expectedVpcCidr {
				r.Equal(expected, info.vpcCidr[i].String())
			}

			r.Len(info.cloudCidr, len(tt.expectedCloudCidr))
			for i, expected := range tt.expectedCloudCidr {
				r.Equal(expected, info.cloudCidr[i].String())
			}

			// Verify cluster CIDR is aggregate of all
			expectedClusterCidrCount := len(tt.expectedPodCidr) + len(tt.expectedServiceCidr) +
				len(tt.expectedNodeCidr) + len(tt.expectedVpcCidr) + len(tt.expectedCloudCidr)
			r.Len(info.clusterCidr, expectedClusterCidrCount)
			info.mu.RUnlock()
		})
	}
}

type mockKubeClientWithRetry struct {
	response   *kubepb.GetClusterInfoResponse
	err        error
	currentTry int
	mu         sync.Mutex
}

func (m *mockKubeClientWithRetry) GetClusterInfo(ctx context.Context, req *kubepb.GetClusterInfoRequest, opts ...grpc.CallOption) (*kubepb.GetClusterInfoResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return nil, m.err
	}
	return m.response, nil
}

func (m *mockKubeClientWithRetry) GetCloudVolumes(ctx context.Context, in *kubepb.GetCloudVolumesRequest, opts ...grpc.CallOption) (*kubepb.GetCloudVolumesResponse, error) {
	return &kubepb.GetCloudVolumesResponse{}, nil
}

func (m *mockKubeClientWithRetry) GetIPsInfo(ctx context.Context, in *kubepb.GetIPsInfoRequest, opts ...grpc.CallOption) (*kubepb.GetIPsInfoResponse, error) {
	return &kubepb.GetIPsInfoResponse{}, nil
}

func (m *mockKubeClientWithRetry) GetIPInfo(ctx context.Context, in *kubepb.GetIPInfoRequest, opts ...grpc.CallOption) (*kubepb.GetIPInfoResponse, error) {
	return nil, nil
}

func (m *mockKubeClientWithRetry) GetPod(ctx context.Context, in *kubepb.GetPodRequest, opts ...grpc.CallOption) (*kubepb.GetPodResponse, error) {
	return &kubepb.GetPodResponse{Pod: &kubepb.Pod{}}, nil
}

func (m *mockKubeClientWithRetry) GetNode(ctx context.Context, req *kubepb.GetNodeRequest, opts ...grpc.CallOption) (*kubepb.GetNodeResponse, error) {
	return &kubepb.GetNodeResponse{Node: &kubepb.Node{Labels: make(map[string]string)}}, nil
}

func (m *mockKubeClientWithRetry) GetNodeStatsSummary(ctx context.Context, req *kubepb.GetNodeStatsSummaryRequest, opts ...grpc.CallOption) (*kubepb.GetNodeStatsSummaryResponse, error) {
	return &kubepb.GetNodeStatsSummaryResponse{Node: &kubepb.NodeStats{NodeName: req.NodeName}}, nil
}

func (m *mockKubeClientWithRetry) GetPodVolumes(ctx context.Context, in *kubepb.GetPodVolumesRequest, opts ...grpc.CallOption) (*kubepb.GetPodVolumesResponse, error) {
	return &kubepb.GetPodVolumesResponse{}, nil
}
