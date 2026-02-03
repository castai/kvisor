package kube

import (
	"context"
	"encoding/json"
	"fmt"

	kubepb "github.com/castai/kvisor/api/v1/kube"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NodeStatsSummary represents the summary API response from kubelet.
// This matches the structure returned by /api/v1/nodes/{name}/proxy/stats/summary
type NodeStatsSummary struct {
	Node nodeStatsJSON  `json:"node"`
	Pods []podStatsJSON `json:"pods"`
}

type podStatsJSON struct {
	PodRef           podRefJSON   `json:"podRef"`
	EphemeralStorage *fsStatsJSON `json:"ephemeral-storage,omitempty"`
}

type podRefJSON struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	UID       string `json:"uid"`
}

type nodeStatsJSON struct {
	NodeName  string             `json:"nodeName"`
	StartTime metav1.Time        `json:"startTime"`
	CPU       *cpuStatsJSON      `json:"cpu,omitempty"`
	Memory    *memoryStatsJSON   `json:"memory,omitempty"`
	Network   *networkStatsJSON  `json:"network,omitempty"`
	Fs        *fsStatsJSON       `json:"fs,omitempty"`
	Runtime   *runtimeStatsJSON  `json:"runtime,omitempty"`
}

type cpuStatsJSON struct {
	Time                 metav1.Time `json:"time"`
	UsageNanoCores       *uint64     `json:"usageNanoCores,omitempty"`
	UsageCoreNanoSeconds *uint64     `json:"usageCoreNanoSeconds,omitempty"`
}

type memoryStatsJSON struct {
	Time            metav1.Time `json:"time"`
	AvailableBytes  *uint64     `json:"availableBytes,omitempty"`
	UsageBytes      *uint64     `json:"usageBytes,omitempty"`
	WorkingSetBytes *uint64     `json:"workingSetBytes,omitempty"`
	RSSBytes        *uint64     `json:"rssBytes,omitempty"`
	PageFaults      *uint64     `json:"pageFaults,omitempty"`
	MajorPageFaults *uint64     `json:"majorPageFaults,omitempty"`
}

type networkStatsJSON struct {
	Time     metav1.Time `json:"time"`
	RxBytes  *uint64     `json:"rxBytes,omitempty"`
	RxErrors *uint64     `json:"rxErrors,omitempty"`
	TxBytes  *uint64     `json:"txBytes,omitempty"`
	TxErrors *uint64     `json:"txErrors,omitempty"`
}

type fsStatsJSON struct {
	Time           metav1.Time `json:"time"`
	AvailableBytes *uint64     `json:"availableBytes,omitempty"`
	CapacityBytes  *uint64     `json:"capacityBytes,omitempty"`
	UsedBytes      *uint64     `json:"usedBytes,omitempty"`
	InodesFree     *uint64     `json:"inodesFree,omitempty"`
	Inodes         *uint64     `json:"inodes,omitempty"`
	InodesUsed     *uint64     `json:"inodesUsed,omitempty"`
}

type runtimeStatsJSON struct {
	ImageFs     *fsStatsJSON `json:"imageFs,omitempty"`
	ContainerFs *fsStatsJSON `json:"containerFs,omitempty"`
}

// GetNodeStatsSummary retrieves stats summary for a given node from the kubelet stats API.
func (c *Client) GetNodeStatsSummary(ctx context.Context, nodeName string) (*kubepb.GetNodeStatsSummaryResponse, error) {
	// Make the proxy request to the node's stats/summary endpoint
	result := c.client.CoreV1().RESTClient().
		Get().
		Resource("nodes").
		Name(nodeName).
		SubResource("proxy").
		Suffix("stats/summary").
		Do(ctx)

	// Get the raw response
	rawData, err := result.Raw()
	if err != nil {
		return nil, fmt.Errorf("failed to get node stats summary: %w", err)
	}

	// Parse the JSON response
	var summary NodeStatsSummary
	if err := json.Unmarshal(rawData, &summary); err != nil {
		return nil, fmt.Errorf("failed to unmarshal stats summary: %w", err)
	}

	// Convert to protobuf response
	return convertToProto(&summary), nil
}

// convertToProto converts the JSON response to protobuf format
func convertToProto(summary *NodeStatsSummary) *kubepb.GetNodeStatsSummaryResponse {
	return &kubepb.GetNodeStatsSummaryResponse{
		Node: convertNodeStats(&summary.Node),
	}
}

func convertNodeStats(node *nodeStatsJSON) *kubepb.NodeStats {
	stats := &kubepb.NodeStats{
		NodeName:         node.NodeName,
		StartTimeSeconds: node.StartTime.Unix(),
	}

	if node.CPU != nil {
		stats.Cpu = convertCPUStats(node.CPU)
	}
	if node.Memory != nil {
		stats.Memory = convertMemoryStats(node.Memory)
	}
	if node.Network != nil {
		stats.Network = convertNetworkStats(node.Network)
	}
	if node.Fs != nil {
		stats.Fs = convertFsStats(node.Fs)
	}
	if node.Runtime != nil {
		stats.Runtime = convertRuntimeStats(node.Runtime)
	}

	return stats
}

func convertCPUStats(cpu *cpuStatsJSON) *kubepb.CPUStats {
	stats := &kubepb.CPUStats{
		TimeSeconds: cpu.Time.Unix(),
	}
	if cpu.UsageNanoCores != nil {
		stats.UsageNanocores = *cpu.UsageNanoCores
	}
	if cpu.UsageCoreNanoSeconds != nil {
		stats.UsageCoreNanoseconds = *cpu.UsageCoreNanoSeconds
	}
	return stats
}

func convertMemoryStats(mem *memoryStatsJSON) *kubepb.MemoryStats {
	stats := &kubepb.MemoryStats{
		TimeSeconds: mem.Time.Unix(),
	}
	if mem.AvailableBytes != nil {
		stats.AvailableBytes = *mem.AvailableBytes
	}
	if mem.UsageBytes != nil {
		stats.UsageBytes = *mem.UsageBytes
	}
	if mem.WorkingSetBytes != nil {
		stats.WorkingSetBytes = *mem.WorkingSetBytes
	}
	if mem.RSSBytes != nil {
		stats.RssBytes = *mem.RSSBytes
	}
	if mem.PageFaults != nil {
		stats.PageFaults = *mem.PageFaults
	}
	if mem.MajorPageFaults != nil {
		stats.MajorPageFaults = *mem.MajorPageFaults
	}
	return stats
}

func convertNetworkStats(net *networkStatsJSON) *kubepb.NetworkStats {
	stats := &kubepb.NetworkStats{
		TimeSeconds: net.Time.Unix(),
	}
	if net.RxBytes != nil {
		stats.RxBytes = *net.RxBytes
	}
	if net.RxErrors != nil {
		stats.RxErrors = *net.RxErrors
	}
	if net.TxBytes != nil {
		stats.TxBytes = *net.TxBytes
	}
	if net.TxErrors != nil {
		stats.TxErrors = *net.TxErrors
	}
	return stats
}

func convertFsStats(fs *fsStatsJSON) *kubepb.FsStats {
	stats := &kubepb.FsStats{
		TimeSeconds: fs.Time.Unix(),
	}
	if fs.AvailableBytes != nil {
		stats.AvailableBytes = *fs.AvailableBytes
	}
	if fs.CapacityBytes != nil {
		stats.CapacityBytes = *fs.CapacityBytes
	}
	if fs.UsedBytes != nil {
		stats.UsedBytes = *fs.UsedBytes
	}
	if fs.InodesFree != nil {
		stats.InodesFree = *fs.InodesFree
	}
	if fs.Inodes != nil {
		stats.Inodes = *fs.Inodes
	}
	if fs.InodesUsed != nil {
		stats.InodesUsed = *fs.InodesUsed
	}
	return stats
}

func convertRuntimeStats(runtime *runtimeStatsJSON) *kubepb.RuntimeStats {
	stats := &kubepb.RuntimeStats{}
	if runtime.ImageFs != nil {
		stats.ImageFs = convertFsStats(runtime.ImageFs)
		stats.TimeSeconds = runtime.ImageFs.Time.Unix()
	}
	if runtime.ContainerFs != nil {
		stats.ContainerFs = convertFsStats(runtime.ContainerFs)
		if stats.TimeSeconds == 0 {
			stats.TimeSeconds = runtime.ContainerFs.Time.Unix()
		}
	}
	return stats
}

// GetNodeStatsSummaryWithPods retrieves the full stats summary including pod data
func (c *Client) GetNodeStatsSummaryWithPods(ctx context.Context, nodeName string) (*NodeStatsSummary, error) {
	result := c.client.CoreV1().RESTClient().
		Get().
		Resource("nodes").
		Name(nodeName).
		SubResource("proxy").
		Suffix("stats/summary").
		Do(ctx)

	rawData, err := result.Raw()
	if err != nil {
		return nil, fmt.Errorf("failed to get node stats summary: %w", err)
	}

	var summary NodeStatsSummary
	if err := json.Unmarshal(rawData, &summary); err != nil {
		return nil, fmt.Errorf("failed to unmarshal stats summary: %w", err)
	}

	return &summary, nil
}
