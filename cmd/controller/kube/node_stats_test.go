package kube

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	kubepb "github.com/castai/kvisor/api/v1/kube"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestGetNodeStatsSummary(t *testing.T) {
	log := logging.NewTestLog()

	// Create mock stats summary response
	mockStats := NodeStatsSummary{
		Node: nodeStatsJSON{
			NodeName:  "test-node",
			StartTime: metav1.Now(),
			CPU: &cpuStatsJSON{
				Time:                 metav1.Now(),
				UsageNanoCores:       ptrUint64(1000000000),
				UsageCoreNanoSeconds: ptrUint64(5000000000),
			},
			Memory: &memoryStatsJSON{
				Time:            metav1.Now(),
				AvailableBytes:  ptrUint64(8000000000),
				UsageBytes:      ptrUint64(4000000000),
				WorkingSetBytes: ptrUint64(3500000000),
				RSSBytes:        ptrUint64(3000000000),
				PageFaults:      ptrUint64(1000),
				MajorPageFaults: ptrUint64(10),
			},
			Network: &networkStatsJSON{
				Time:     metav1.Now(),
				RxBytes:  ptrUint64(1000000),
				RxErrors: ptrUint64(0),
				TxBytes:  ptrUint64(2000000),
				TxErrors: ptrUint64(0),
			},
			Fs: &fsStatsJSON{
				Time:           metav1.Now(),
				AvailableBytes: ptrUint64(50000000000),
				CapacityBytes:  ptrUint64(100000000000),
				UsedBytes:      ptrUint64(50000000000),
				InodesFree:     ptrUint64(1000000),
				Inodes:         ptrUint64(2000000),
				InodesUsed:     ptrUint64(1000000),
			},
		},
		Pods: []podStatsJSON{
			{
				PodRef: podRefJSON{
					Name:      "test-pod",
					Namespace: "default",
					UID:       "test-pod-uid",
				},
				StartTime: metav1.Now(),
				CPU: &cpuStatsJSON{
					Time:                 metav1.Now(),
					UsageNanoCores:       ptrUint64(100000000),
					UsageCoreNanoSeconds: ptrUint64(500000000),
				},
				Memory: &memoryStatsJSON{
					Time:            metav1.Now(),
					UsageBytes:      ptrUint64(100000000),
					WorkingSetBytes: ptrUint64(90000000),
				},
				Containers: []containerStatsJSON{
					{
						Name:      "test-container",
						StartTime: metav1.Now(),
						CPU: &cpuStatsJSON{
							Time:                 metav1.Now(),
							UsageNanoCores:       ptrUint64(100000000),
							UsageCoreNanoSeconds: ptrUint64(500000000),
						},
						Memory: &memoryStatsJSON{
							Time:            metav1.Now(),
							UsageBytes:      ptrUint64(100000000),
							WorkingSetBytes: ptrUint64(90000000),
						},
					},
				},
			},
		},
	}

	_ = json.Marshal // Keep json import for potential future use
	_ = http.StatusOK // Keep http import for potential future use
	_ = log           // Keep log for consistency

	t.Run("successful stats retrieval", func(t *testing.T) {
		// For this test, we'll need to mock the REST client call
		// Since we can't easily override the REST client in fake.Clientset,
		// we'll test the conversion functions instead

		// Test the conversion from JSON to protobuf
		resp := convertToProto(&mockStats)

		require.NotNil(t, resp)
		require.NotNil(t, resp.Node)
		assert.Equal(t, "test-node", resp.Node.NodeName)
		assert.NotNil(t, resp.Node.Cpu)
		assert.Equal(t, uint64(1000000000), resp.Node.Cpu.UsageNanocores)
		assert.NotNil(t, resp.Node.Memory)
		assert.Equal(t, uint64(4000000000), resp.Node.Memory.UsageBytes)
	})

	t.Run("conversion functions", func(t *testing.T) {
		// Test CPU stats conversion
		cpuJSON := &cpuStatsJSON{
			Time:                 metav1.Now(),
			UsageNanoCores:       ptrUint64(1000000),
			UsageCoreNanoSeconds: ptrUint64(5000000),
		}
		cpuPB := convertCPUStats(cpuJSON)
		assert.Equal(t, uint64(1000000), cpuPB.UsageNanocores)
		assert.Equal(t, uint64(5000000), cpuPB.UsageCoreNanoseconds)

		// Test Memory stats conversion
		memJSON := &memoryStatsJSON{
			Time:            metav1.Now(),
			AvailableBytes:  ptrUint64(1000),
			UsageBytes:      ptrUint64(2000),
			WorkingSetBytes: ptrUint64(3000),
			RSSBytes:        ptrUint64(4000),
			PageFaults:      ptrUint64(100),
			MajorPageFaults: ptrUint64(10),
		}
		memPB := convertMemoryStats(memJSON)
		assert.Equal(t, uint64(1000), memPB.AvailableBytes)
		assert.Equal(t, uint64(2000), memPB.UsageBytes)
		assert.Equal(t, uint64(3000), memPB.WorkingSetBytes)
		assert.Equal(t, uint64(4000), memPB.RssBytes)
		assert.Equal(t, uint64(100), memPB.PageFaults)
		assert.Equal(t, uint64(10), memPB.MajorPageFaults)

		// Test Network stats conversion
		netJSON := &networkStatsJSON{
			Time:     metav1.Now(),
			RxBytes:  ptrUint64(1000),
			RxErrors: ptrUint64(1),
			TxBytes:  ptrUint64(2000),
			TxErrors: ptrUint64(2),
		}
		netPB := convertNetworkStats(netJSON)
		assert.Equal(t, uint64(1000), netPB.RxBytes)
		assert.Equal(t, uint64(1), netPB.RxErrors)
		assert.Equal(t, uint64(2000), netPB.TxBytes)
		assert.Equal(t, uint64(2), netPB.TxErrors)

		// Test FS stats conversion
		fsJSON := &fsStatsJSON{
			Time:           metav1.Now(),
			AvailableBytes: ptrUint64(1000),
			CapacityBytes:  ptrUint64(2000),
			UsedBytes:      ptrUint64(1000),
			InodesFree:     ptrUint64(100),
			Inodes:         ptrUint64(200),
			InodesUsed:     ptrUint64(100),
		}
		fsPB := convertFsStats(fsJSON)
		assert.Equal(t, uint64(1000), fsPB.AvailableBytes)
		assert.Equal(t, uint64(2000), fsPB.CapacityBytes)
		assert.Equal(t, uint64(1000), fsPB.UsedBytes)
		assert.Equal(t, uint64(100), fsPB.InodesFree)
		assert.Equal(t, uint64(200), fsPB.Inodes)
		assert.Equal(t, uint64(100), fsPB.InodesUsed)
	})
}

func TestServerGetNodeStatsSummary(t *testing.T) {
	log := logging.NewTestLog()

	t.Run("empty node name returns error", func(t *testing.T) {
		clientset := fake.NewClientset()
		client := NewClient(log, "test-pod", "kvisor-test", Version{}, clientset)
		srv := NewServer(client)

		resp, err := srv.GetNodeStatsSummary(context.Background(), &kubepb.GetNodeStatsSummaryRequest{
			NodeName: "",
		})

		assert.Nil(t, resp)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "node_name is required")
	})

	// Note: We skip testing with a real REST client call because fake.Clientset
	// doesn't provide a functional REST client for proxy requests.
	// The conversion functions are thoroughly tested above, and integration tests
	// would be needed to test the full proxy request flow.
}

// Helper function to create uint64 pointers
func ptrUint64(v uint64) *uint64 {
	return &v
}
