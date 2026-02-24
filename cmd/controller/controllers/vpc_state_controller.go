package controllers

import (
	"context"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/castai/kvisor/cmd/controller/kube"
	cloudtypes "github.com/castai/kvisor/pkg/cloudprovider/types"
	"github.com/castai/logging"
)

type VPCStateControllerConfig struct {
	Enabled   bool `json:"enabled"`
	UseZoneID bool `json:"useZoneID"`
	NetworkName     string        `json:"networkName"`
	RefreshInterval time.Duration `json:"refreshInterval"`
	CacheSize       uint32        `json:"cacheSize"`
	StaticCIDRsFile string        `json:"staticCIDRsFile"` // Path to YAML file
}

// StaticCIDRMapping represents a manual CIDR to zone/region/service mapping.
type StaticCIDRMapping struct {
	CIDR string `json:"cidr" yaml:"cidr"`
	Zone string `json:"zone" yaml:"zone"` // AWS zone name (e.g., "us-east-1a") or zone ID (e.g., "use1-az1") depending on controller config
	Region             string `json:"region" yaml:"region"`
	WorkloadName       string `json:"name" yaml:"name"`
	WorkloadKind       string `json:"kind" yaml:"kind"`
	ConnectivityMethod string `json:"connectivityMethod" yaml:"connectivityMethod"`
}

type cloudProvider interface {
	Type() cloudtypes.Type
	GetNetworkState(ctx context.Context) (*cloudtypes.NetworkState, error)
	RefreshNetworkState(ctx context.Context, network string) error
}

func NewVPCStateController(log *logging.Logger, cfg VPCStateControllerConfig, cloudProvider cloudProvider, vpcIndex *kube.VPCIndex) *VPCStateController {
	if cfg.RefreshInterval == 0 {
		cfg.RefreshInterval = 1 * time.Hour
	}
	return &VPCStateController{
		log:           log.WithField("component", "vpc_state_controller"),
		cfg:           cfg,
		cloudProvider: cloudProvider,
		vpcIndex:      vpcIndex,
	}
}

type VPCStateController struct {
	log           *logging.Logger
	cfg           VPCStateControllerConfig
	cloudProvider cloudProvider
	vpcIndex      *kube.VPCIndex
}

func (c *VPCStateController) Run(ctx context.Context) error {
	c.log.Infof("running VPC cloud sync for provider: %s", c.cloudProvider.Type())
	defer c.log.Info("stopping VPC cloud sync")

	if err := c.fetchInitialNetworkState(ctx, c.vpcIndex); err != nil {
		c.log.Errorf("failed to fetch initial VPC state: %v", err)
		return nil
	}

	return c.runRefreshLoop(ctx, c.vpcIndex)
}

func (c *VPCStateController) fetchInitialNetworkState(ctx context.Context, vpcIndex *kube.VPCIndex) error {
	backoff := 2 * time.Second
	maxRetries := 5

	for i := 0; i < maxRetries; i++ {
		err := c.cloudProvider.RefreshNetworkState(ctx, c.cfg.NetworkName)
		if err != nil {
			c.log.Errorf("VPC state refresh failed: %v", err)
			continue
		}
		state, err := c.cloudProvider.GetNetworkState(ctx)
		if err == nil {
			if err := vpcIndex.Update(state); err != nil {
				c.log.Errorf("failed to update VPC index: %v", err)
			} else {
				c.log.Info("initial VPC state loaded successfully")
				return nil
			}
		}

		if i < maxRetries-1 {
			c.log.Warnf("VPC state fetch attempt %d/%d failed: %v, retrying in %v", i+1, maxRetries, err, backoff)
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

	c.log.Errorf("failed to fetch initial VPC state after %d attempts", maxRetries)
	return nil
}

func (c *VPCStateController) runRefreshLoop(ctx context.Context, vpcIndex *kube.VPCIndex) error {
	ticker := time.NewTicker(c.cfg.RefreshInterval)
	defer ticker.Stop()

	c.log.Infof("starting VPC state refresh (interval: %v)", c.cfg.RefreshInterval)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			err := c.cloudProvider.RefreshNetworkState(ctx, c.cfg.NetworkName)
			if err != nil {
				c.log.Errorf("VPC state refresh failed: %v", err)
				continue
			}

			state, err := c.cloudProvider.GetNetworkState(ctx)
			if err != nil {
				c.log.Errorf("VPC state loading failed: %v", err)
				continue
			}

			if err := vpcIndex.Update(state); err != nil {
				c.log.Errorf("failed to update VPC index: %v", err)
				continue
			}

			c.log.Debug("VPC state refreshed successfully")
		}
	}
}

// LoadStaticCIDRsFromFile loads static CIDRs from a YAML file.
// ConfigMaps can be mounted as files, so this also supports ConfigMap-based configuration.
func LoadStaticCIDRsFromFile(log *logging.Logger, path string, vpcIndex *kube.VPCIndex) error {
	if path == "" {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading file: %w", err)
	}

	var config struct {
		StaticCIDRMappings []StaticCIDRMapping `yaml:"staticCIDRMappings"`
	}

	if err := yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("parsing YAML: %w", err)
	}

	entries := convertStaticMappingsToEntries(config.StaticCIDRMappings)
	log.Infof("loaded %d static CIDR mappings from file %s", len(entries), path)
	return vpcIndex.AddStaticCIDRs(entries)
}

// convertStaticMappingsToEntries converts config mappings to VPCIndex entries.
func convertStaticMappingsToEntries(mappings []StaticCIDRMapping) []kube.StaticCIDREntry {
	entries := make([]kube.StaticCIDREntry, len(mappings))
	for i, m := range mappings {
		entries[i] = kube.StaticCIDREntry{
			CIDR:               m.CIDR,
			Zone:               m.Zone,
			Region:             m.Region,
			WorkloadName:       m.WorkloadName,
			WorkloadKind:       m.WorkloadKind,
			ConnectivityMethod: m.ConnectivityMethod,
		}
	}
	return entries
}
