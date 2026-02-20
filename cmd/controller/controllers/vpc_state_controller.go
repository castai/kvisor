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
	Enabled            bool                  `json:"enabled"`
	NetworkName        string                `json:"networkName"`
	RefreshInterval    time.Duration         `json:"refreshInterval"`
	CacheSize          uint32                `json:"CacheSize"`
	StaticCIDRMappings []StaticCIDRMapping   `json:"staticCIDRMappings"` // Direct config
	StaticCIDRsFile    string                `json:"staticCIDRsFile"`    // Path to YAML file
}

// StaticCIDRMapping represents a manual CIDR to zone/region/service mapping.
type StaticCIDRMapping struct {
	CIDR               string `json:"cidr" yaml:"cidr"`
	Zone               string `json:"zone" yaml:"zone"`                         // AWS zone name (e.g., "us-east-1a") - optional
	ZoneId             string `json:"zoneId" yaml:"zoneId"`                     // AWS zone ID (e.g., "use1-az1") - for cross-account
	Region             string `json:"region" yaml:"region"`
	WorkloadName       string `json:"workloadName" yaml:"workloadName"`
	WorkloadKind       string `json:"workloadKind" yaml:"workloadKind"`
	ConnectivityMethod string `json:"connectivityMethod" yaml:"connectivityMethod"`
	Description        string `json:"description" yaml:"description"`           // Optional human-readable note
}

type cloudProvider interface {
	Type() cloudtypes.Type
	GetNetworkState(ctx context.Context) (*cloudtypes.NetworkState, error)
	RefreshNetworkState(ctx context.Context, network string) error
}

func NewVPCStateController(log *logging.Logger, cfg VPCStateControllerConfig, cloudProvider cloudProvider, kubeClient *kube.Client) *VPCStateController {
	if cfg.RefreshInterval == 0 {
		cfg.RefreshInterval = 1 * time.Hour
	}
	return &VPCStateController{
		log:           log.WithField("component", "vpc_state_controller"),
		cfg:           cfg,
		cloudProvider: cloudProvider,
		kubeClient:    kubeClient,
	}
}

type VPCStateController struct {
	log           *logging.Logger
	cfg           VPCStateControllerConfig
	cloudProvider cloudProvider
	kubeClient    *kube.Client
}

func (c *VPCStateController) Run(ctx context.Context) error {
	c.log.Infof("running for cloud provider: %s", c.cloudProvider.Type())
	defer c.log.Infof("stopping")

	vpcIndex := kube.NewVPCIndex(c.log, c.cfg.RefreshInterval, c.cfg.CacheSize)

	// Load static CIDR mappings if configured
	if err := c.loadStaticCIDRs(ctx, vpcIndex); err != nil {
		c.log.Warnf("failed to load static CIDRs: %v", err)
		// Non-fatal - continue with cloud discovery only
	}

	if err := c.fetchInitialNetworkState(ctx, vpcIndex); err != nil {
		c.log.Errorf("failed to fetch initial VPC state: %v", err)
		return nil
	}

	c.kubeClient.SetVPCIndex(vpcIndex)

	return c.runRefreshLoop(ctx, vpcIndex)
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

// loadStaticCIDRs loads static CIDR mappings from config or file.
func (c *VPCStateController) loadStaticCIDRs(ctx context.Context, vpcIndex *kube.VPCIndex) error {
	// Option 1: Load from config struct (direct)
	if len(c.cfg.StaticCIDRMappings) > 0 {
		entries := convertStaticMappingsToEntries(c.cfg.StaticCIDRMappings)
		c.log.Infof("loaded %d static CIDR mappings from config", len(entries))
		return vpcIndex.AddStaticCIDRs(entries)
	}

	// Option 2: Load from YAML file (or ConfigMap mounted as file)
	if c.cfg.StaticCIDRsFile != "" {
		return c.loadStaticCIDRsFromFile(c.cfg.StaticCIDRsFile, vpcIndex)
	}

	return nil
}

// loadStaticCIDRsFromFile loads static CIDRs from a YAML file.
// ConfigMaps can be mounted as files, so this also supports ConfigMap-based configuration.
func (c *VPCStateController) loadStaticCIDRsFromFile(path string, vpcIndex *kube.VPCIndex) error {
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
	c.log.Infof("loaded %d static CIDR mappings from file %s", len(entries), path)
	return vpcIndex.AddStaticCIDRs(entries)
}

// convertStaticMappingsToEntries converts config mappings to VPCIndex entries.
func convertStaticMappingsToEntries(mappings []StaticCIDRMapping) []kube.StaticCIDREntry {
	entries := make([]kube.StaticCIDREntry, len(mappings))
	for i, m := range mappings {
		entries[i] = kube.StaticCIDREntry{
			CIDR:               m.CIDR,
			Zone:               m.Zone,
			ZoneId:             m.ZoneId,
			Region:             m.Region,
			WorkloadName:       m.WorkloadName,
			WorkloadKind:       m.WorkloadKind,
			ConnectivityMethod: m.ConnectivityMethod,
		}
	}
	return entries
}
