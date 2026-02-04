package controllers

import (
	"context"
	"strings"
	"time"

	"github.com/castai/kvisor/cmd/controller/kube"
	cloudtypes "github.com/castai/kvisor/pkg/cloudprovider/types"
	"github.com/castai/kvisor/pkg/logging"
)

type VolumeStateControllerConfig struct {
	Enabled         bool          `json:"enabled"`
	RefreshInterval time.Duration `json:"refreshInterval"`
}

type cloudProviderVolume interface {
	Type() cloudtypes.Type
	GetStorageState(ctx context.Context, instanceIds ...string) (*cloudtypes.StorageState, error)
}

func NewVolumeStateController(log *logging.Logger, cfg VolumeStateControllerConfig, cloudProvider cloudProviderVolume, kubeClient *kube.Client) *VolumeStateController {
	if cfg.RefreshInterval == 0 {
		cfg.RefreshInterval = 5 * time.Minute
	}
	return &VolumeStateController{
		log:           log.WithField("component", "volume_state_controller"),
		cfg:           cfg,
		cloudProvider: cloudProvider,
		kubeClient:    kubeClient,
	}
}

type VolumeStateController struct {
	log           *logging.Logger
	cfg           VolumeStateControllerConfig
	cloudProvider cloudProviderVolume
	kubeClient    *kube.Client
}

func (c *VolumeStateController) Run(ctx context.Context) error {
	c.log.Infof("running for cloud provider: %s", c.cloudProvider.Type())
	defer c.log.Infof("stopping")

	volumeIndex := kube.NewVolumeIndex(c.log)

	if err := c.fetchInitialStorageState(ctx, volumeIndex); err != nil {
		c.log.Errorf("failed to fetch initial storage state: %v", err)
		return nil
	}

	c.kubeClient.SetVolumeIndex(volumeIndex)

	return c.runRefreshLoop(ctx, volumeIndex)
}

func (c *VolumeStateController) fetchInitialStorageState(ctx context.Context, volumeIndex *kube.VolumeIndex) error {
	backoff := 2 * time.Second
	maxRetries := 5

	for i := 0; i < maxRetries; i++ {
		nodes := c.kubeClient.GetAllNodes()
		if len(nodes) == 0 {
			return nil
		}

		instanceIDs := make([]string, 0, len(nodes))
		instanceIDToNodeName := make(map[string]string, len(nodes))
		for _, node := range nodes {
			instanceID := extractInstanceIDFromProviderID(node.Spec.ProviderID)
			if instanceID == "" {
				c.log.WithField("provider_id", node.Spec.ProviderID).Warn("could not extract instance id from provider id")
				continue
			}
			instanceIDs = append(instanceIDs, instanceID)
			instanceIDToNodeName[instanceID] = node.Name
		}

		state, err := c.cloudProvider.GetStorageState(ctx, instanceIDs...)
		if err == nil {
			nodeVolumes := mapInstanceVolumesToNodeVolumes(state.InstanceVolumes, instanceIDToNodeName)
			volumeIndex.UpdateNodeVolumes(nodeVolumes)
			return nil
		}

		if i < maxRetries-1 {
			c.log.Warnf("storage state fetch attempt %d/%d failed: %v, retrying in %v", i+1, maxRetries, err, backoff)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
				backoff *= 2
				if backoff > 30*time.Second {
					backoff = 30 * time.Second
				}
			}
		}
	}

	c.log.Errorf("failed to fetch initial storage state after %d attempts", maxRetries)
	return nil
}

func (c *VolumeStateController) runRefreshLoop(ctx context.Context, volumeIndex *kube.VolumeIndex) error {
	ticker := time.NewTicker(c.cfg.RefreshInterval)
	defer ticker.Stop()

	c.log.Debugf("starting storage state refresh (interval: %v)", c.cfg.RefreshInterval)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			nodes := c.kubeClient.GetAllNodes()
			if len(nodes) == 0 {
				continue
			}

			instanceIDs := make([]string, 0, len(nodes))
			instanceIDToNodeName := make(map[string]string, len(nodes))
			for _, node := range nodes {
				instanceID := extractInstanceIDFromProviderID(node.Spec.ProviderID)
				if instanceID == "" {
					c.log.WithField("provider_id", node.Spec.ProviderID).Warn("could not extract instance id from provider id")
					continue
				}
				instanceIDs = append(instanceIDs, instanceID)
				instanceIDToNodeName[instanceID] = node.Name
			}

			state, err := c.cloudProvider.GetStorageState(ctx, instanceIDs...)
			if err != nil {
				c.log.Errorf("storage state loading failed: %v", err)
				continue
			}

			nodeVolumes := mapInstanceVolumesToNodeVolumes(state.InstanceVolumes, instanceIDToNodeName)
			volumeIndex.UpdateNodeVolumes(nodeVolumes)

			c.log.Debug("storage state refreshed successfully")
		}
	}
}

// mapInstanceVolumesToNodeVolumes converts a map of instance ID -> volumes to node name -> volumes.
func mapInstanceVolumesToNodeVolumes(instanceVolumes map[string][]cloudtypes.Volume, instanceIDToNodeName map[string]string) map[string][]cloudtypes.Volume {
	nodeVolumes := make(map[string][]cloudtypes.Volume, len(instanceVolumes))
	for instanceID, volumes := range instanceVolumes {
		if nodeName, ok := instanceIDToNodeName[instanceID]; ok {
			nodeVolumes[nodeName] = volumes
		}
	}
	return nodeVolumes
}

// extractInstanceIDFromProviderID extracts the cloud instance ID from a node spec.providerID.
func extractInstanceIDFromProviderID(providerID string) string {
	if providerID == "" {
		return ""
	}

	// AWS format: aws:///zone/instance-id or aws://account-id/zone/instance-id
	if strings.HasPrefix(providerID, "aws://") {
		parts := strings.Split(providerID, "/")
		if len(parts) > 0 {
			return parts[len(parts)-1]
		}
	}

	// GCP format: gce://project-id/zone/instance-name
	if instanceID, ok := strings.CutPrefix(providerID, "gce://"); ok {
		parts := strings.Split(instanceID, "/")
		if len(parts) == 3 {
			return instanceID
		}
	}

	// Azure format: azure:///subscriptions/.../virtualMachines/vm-name
	if strings.HasPrefix(providerID, "azure://") {
		parts := strings.Split(providerID, "/")
		if len(parts) > 0 {
			return parts[len(parts)-1]
		}
	}

	return ""
}
