package gpu

import (
	"context"
	"testing"

	kubepb "github.com/castai/kvisor/api/v1/kube"
	"google.golang.org/grpc"
)

type mockKubeAPIClient struct {
	kubepb.KubeAPIClient
	getPodByNameCalls int
	getPodByNameResp  *kubepb.GetPodResponse
}

func (m *mockKubeAPIClient) GetPodByName(_ context.Context, _ *kubepb.GetPodByNameRequest, _ ...grpc.CallOption) (*kubepb.GetPodResponse, error) {
	m.getPodByNameCalls++
	return m.getPodByNameResp, nil
}

func TestWorkloadLookupCache(t *testing.T) {
	mock := &mockKubeAPIClient{
		getPodByNameResp: &kubepb.GetPodResponse{
			Pod: &kubepb.Pod{
				WorkloadName: "my-deploy",
				WorkloadKind: kubepb.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT,
			},
		},
	}

	lookup, err := newWorkloadLookup(mock, nil, 512)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	// First call should hit the gRPC client.
	name, kind, err := lookup.FindWorkloadForPod(ctx, "pod-1", "ns-1")
	if err != nil {
		t.Fatal(err)
	}
	if name != "my-deploy" || kind != "Deployment" {
		t.Fatalf("unexpected result: %s %s", name, kind)
	}
	if mock.getPodByNameCalls != 1 {
		t.Fatalf("expected 1 call, got %d", mock.getPodByNameCalls)
	}

	// Second call with same pod should be served from cache.
	name, kind, err = lookup.FindWorkloadForPod(ctx, "pod-1", "ns-1")
	if err != nil {
		t.Fatal(err)
	}
	if name != "my-deploy" || kind != "Deployment" {
		t.Fatalf("unexpected result: %s %s", name, kind)
	}
	if mock.getPodByNameCalls != 1 {
		t.Fatalf("expected 1 call after cache hit, got %d", mock.getPodByNameCalls)
	}

	// Different pod should trigger a new gRPC call.
	_, _, err = lookup.FindWorkloadForPod(ctx, "pod-2", "ns-1")
	if err != nil {
		t.Fatal(err)
	}
	if mock.getPodByNameCalls != 2 {
		t.Fatalf("expected 2 calls after new pod, got %d", mock.getPodByNameCalls)
	}
}
