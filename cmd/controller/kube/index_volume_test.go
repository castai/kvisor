package kube

import (
	"testing"

	cloudtypes "github.com/castai/kvisor/pkg/cloudprovider/types"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/stretchr/testify/require"
)

func TestVolumeIndex(t *testing.T) {
	log := logging.NewTestLog()

	t.Run("new volume index", func(t *testing.T) {
		r := require.New(t)

		index := NewVolumeIndex(log)

		r.NotNil(index)
		r.NotNil(index.log)
		r.NotNil(index.nodeToVolumes)
		r.Empty(index.nodeToVolumes)
	})

	t.Run("update and get volumes", func(t *testing.T) {
		r := require.New(t)
		index := NewVolumeIndex(log)

		volumes := map[string][]cloudtypes.Volume{
			"node-1": {
				{
					VolumeID:        "vol-123",
					VolumeType:      "gp3",
					VolumeState:     "in-use",
					SizeBytes:       107374182400, // 100 GiB
					IOPS:            3000,
					ThroughputBytes: 125829120, // 120 MiB/s
					Encrypted:       true,
					Zone:            "us-east-1a",
				},
			},
			"node-2": {
				{
					VolumeID:    "vol-456",
					VolumeType:  "gp2",
					VolumeState: "in-use",
					SizeBytes:   53687091200, // 50 GiB
					Encrypted:   false,
					Zone:        "us-east-1b",
				},
			},
		}

		index.UpdateNodeVolumes(volumes)

		node1Volumes := index.GetVolumesForNode("node-1")
		r.Len(node1Volumes, 1)
		r.Equal("vol-123", node1Volumes[0].VolumeID)
		r.Equal("gp3", node1Volumes[0].VolumeType)
		r.Equal(int64(107374182400), node1Volumes[0].SizeBytes)
		r.Equal(int32(3000), node1Volumes[0].IOPS)

		node2Volumes := index.GetVolumesForNode("node-2")
		r.Len(node2Volumes, 1)
		r.Equal("vol-456", node2Volumes[0].VolumeID)
		r.Equal("gp2", node2Volumes[0].VolumeType)
	})

	t.Run("get volumes for non-existent node", func(t *testing.T) {
		r := require.New(t)
		index := NewVolumeIndex(log)

		volumes := map[string][]cloudtypes.Volume{
			"node-1": {{VolumeID: "vol-123"}},
		}
		index.UpdateNodeVolumes(volumes)

		nonExistentVolumes := index.GetVolumesForNode("node-3")
		r.Nil(nonExistentVolumes)
	})

	t.Run("update replaces existing", func(t *testing.T) {
		r := require.New(t)
		index := NewVolumeIndex(log)

		initialVolumes := map[string][]cloudtypes.Volume{
			"node-1": {{VolumeID: "vol-123", VolumeType: "gp3"}},
		}
		index.UpdateNodeVolumes(initialVolumes)

		newVolumes := map[string][]cloudtypes.Volume{
			"node-2": {{VolumeID: "vol-456", VolumeType: "gp2"}},
		}
		index.UpdateNodeVolumes(newVolumes)

		// Old node should no longer exist
		node1Volumes := index.GetVolumesForNode("node-1")
		r.Nil(node1Volumes)

		// New node should exist
		node2Volumes := index.GetVolumesForNode("node-2")
		r.Len(node2Volumes, 1)
		r.Equal("vol-456", node2Volumes[0].VolumeID)
	})

	t.Run("multiple volumes per node", func(t *testing.T) {
		r := require.New(t)
		index := NewVolumeIndex(log)

		volumes := map[string][]cloudtypes.Volume{
			"node-1": {
				{VolumeID: "vol-123", VolumeType: "gp3"},
				{VolumeID: "vol-456", VolumeType: "io2"},
				{VolumeID: "vol-789", VolumeType: "gp2"},
			},
		}

		index.UpdateNodeVolumes(volumes)

		node1Volumes := index.GetVolumesForNode("node-1")
		r.Len(node1Volumes, 3)
		r.Equal("vol-123", node1Volumes[0].VolumeID)
		r.Equal("vol-456", node1Volumes[1].VolumeID)
		r.Equal("vol-789", node1Volumes[2].VolumeID)
	})

	t.Run("empty update clears index", func(t *testing.T) {
		r := require.New(t)
		index := NewVolumeIndex(log)

		volumes := map[string][]cloudtypes.Volume{
			"node-1": {{VolumeID: "vol-123"}},
		}
		index.UpdateNodeVolumes(volumes)

		// Update with empty map
		index.UpdateNodeVolumes(map[string][]cloudtypes.Volume{})

		node1Volumes := index.GetVolumesForNode("node-1")
		r.Nil(node1Volumes)
	})
}
