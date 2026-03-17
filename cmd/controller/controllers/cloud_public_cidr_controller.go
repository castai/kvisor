package controllers

import (
	"context"
	"time"

	"github.com/castai/kvisor/cmd/controller/kube"
	"github.com/castai/kvisor/pkg/cloudprovider/serviceranges"
	cloudtypes "github.com/castai/kvisor/pkg/cloudprovider/types"
	"github.com/castai/logging"
)

type CloudPublicCIDRControllerConfig struct {
	CloudProviderType cloudtypes.Type
	RefreshInterval   time.Duration
}

func NewCloudPublicCIDRController(
	log *logging.Logger,
	cfg CloudPublicCIDRControllerConfig,
	vpcIndex *kube.NetworkIndex,
) *CloudPublicCIDRController {
	if cfg.RefreshInterval == 0 {
		cfg.RefreshInterval = 24 * time.Hour
	}
	return &CloudPublicCIDRController{
		log:      log.WithField("component", "cloud_public_cidr_controller"),
		cfg:      cfg,
		vpcIndex: vpcIndex,
	}
}

type CloudPublicCIDRController struct {
	log      *logging.Logger
	cfg      CloudPublicCIDRControllerConfig
	vpcIndex *kube.NetworkIndex
}

func (c *CloudPublicCIDRController) Run(ctx context.Context) error {
	c.log.Infof("running cloud public CIDR fetch for provider: %s", c.cfg.CloudProviderType)
	defer c.log.Info("stopping cloud public CIDR fetch")

	c.fetchWithRetries(ctx)

	ticker := time.NewTicker(c.cfg.RefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			c.fetchOnce(ctx)
		}
	}
}

func (c *CloudPublicCIDRController) fetchWithRetries(ctx context.Context) {
	backoff := 2 * time.Second
	maxRetries := 5

	for i := 0; i < maxRetries; i++ {
		if c.fetchOnce(ctx) {
			return
		}

		if i < maxRetries-1 {
			c.log.Warnf("cloud public CIDR fetch attempt %d/%d failed, retrying in %v", i+1, maxRetries, backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
				backoff *= 2
				if backoff > 30*time.Second {
					backoff = 30 * time.Second
				}
			}
		}
	}

	c.log.Errorf("failed to fetch cloud public CIDRs after %d attempts", maxRetries)
}

func (c *CloudPublicCIDRController) fetchOnce(ctx context.Context) bool {
	ranges, domain, err := serviceranges.FetchServiceIPRanges(ctx, c.log, c.cfg.CloudProviderType)
	if err != nil {
		c.log.Errorf("fetching cloud public service IP ranges: %v", err)
		return false
	}

	if err := c.vpcIndex.UpdateCloudPublicCIDRs(domain, ranges); err != nil {
		c.log.Errorf("updating cloud public CIDRs in VPC index: %v", err)
		return false
	}

	var totalCIDRs int
	for _, r := range ranges {
		totalCIDRs += len(r.CIRDs)
	}
	c.log.Infof("cloud public CIDRs updated: %d entries across %d regions", totalCIDRs, len(ranges))
	return true
}
