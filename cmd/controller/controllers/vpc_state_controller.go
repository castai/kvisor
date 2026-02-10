package controllers

import (
	"context"
	"time"

	"github.com/castai/kvisor/cmd/controller/kube"
	cloudtypes "github.com/castai/kvisor/pkg/cloudprovider/types"
	"github.com/castai/logging"
)

type VPCStateControllerConfig struct {
	Enabled         bool          `json:"enabled"`
	NetworkName     string        `json:"networkName"`
	RefreshInterval time.Duration `json:"refreshInterval"`
	CacheSize       uint32        `json:"CacheSize"`
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
