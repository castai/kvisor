package kube

import (
	"sync"

	cloudtypes "github.com/castai/kvisor/pkg/cloudprovider/types"
	"github.com/castai/logging"
)

// VolumeIndex maintains a mapping of node names to cloud volumes.
type VolumeIndex struct {
	log *logging.Logger

	mu            sync.RWMutex
	nodeToVolumes map[string][]cloudtypes.Volume
}

// NewVolumeIndex creates a new volume index.
func NewVolumeIndex(log *logging.Logger) *VolumeIndex {
	return &VolumeIndex{
		log:           log,
		nodeToVolumes: make(map[string][]cloudtypes.Volume),
	}
}

// Update replaces the entire volume index with a new mapping.
func (i *VolumeIndex) UpdateNodeVolumes(nodeToVolumes map[string][]cloudtypes.Volume) {
	i.mu.Lock()
	defer i.mu.Unlock()

	i.nodeToVolumes = nodeToVolumes
}

// GetVolumesForNode returns volumes attached to a specific node.
func (i *VolumeIndex) GetVolumesForNode(nodeName string) []cloudtypes.Volume {
	i.mu.RLock()
	defer i.mu.RUnlock()

	return i.nodeToVolumes[nodeName]
}
