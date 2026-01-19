package controllers

import (
	"context"
	"time"

	"github.com/castai/kvisor/cmd/controller/kube"
	"github.com/castai/kvisor/pkg/cloudprovider"
	cloudtypes "github.com/castai/kvisor/pkg/cloudprovider/types"
	"github.com/castai/kvisor/pkg/logging"
)

type VPCMetadataConfig struct {
	Enabled           bool          `json:"enabled"`
	Type              string        `json:"type"`
	NetworkName       string        `json:"networkName"`
	RefreshInterval   time.Duration `json:"refreshInterval"`
	CacheSize         uint32        `json:"CacheSize"`
	CredentialsFile   string        `json:"credentialsFile"`
	GCPProjectID      string        `json:"gcpProjectID"`
	AWSAccountID      string        `json:"awsAccountID"`
	AzureSubscription string        `json:"azureSubscription"`
}

func NewVPCMetadataController(log *logging.Logger, cfg VPCMetadataConfig, kubeClient *kube.Client) *VPCMetadataController {
	if cfg.RefreshInterval == 0 {
		cfg.RefreshInterval = 1 * time.Hour
	}
	return &VPCMetadataController{
		log:        log.WithField("component", "vpc_metadata"),
		cfg:        cfg,
		kubeClient: kubeClient,
	}
}

type VPCMetadataController struct {
	log        *logging.Logger
	cfg        VPCMetadataConfig
	kubeClient *kube.Client
}

func (c *VPCMetadataController) Run(ctx context.Context) error {
	c.log.Infof("running for cloud provider: %s", c.cfg.Type)
	defer c.log.Infof("stopping")

	cpConfig := cloudtypes.Config{
		Type:            cloudtypes.Type(c.cfg.Type),
		NetworkName:     c.cfg.NetworkName,
		CredentialsFile: c.cfg.CredentialsFile,
		GCPProjectID:    c.cfg.GCPProjectID,
		AWSAccountID:    c.cfg.AWSAccountID,
	}

	provider, err := cloudprovider.NewProvider(ctx, cpConfig)
	if err != nil {
		c.log.Errorf("failed to initialize cloud provider: %v", err)
		return nil
	}
	defer provider.Close()

	c.log.Infof("cloud provider %s initialized successfully", provider.Type())

	vpcIndex := kube.NewVPCIndex(c.log, c.cfg.RefreshInterval, c.cfg.CacheSize)

	if err := c.fetchInitialMetadata(ctx, provider, vpcIndex); err != nil {
		c.log.Errorf("failed to fetch initial VPC metadata: %v", err)
		return nil
	}

	c.kubeClient.SetVPCIndex(vpcIndex)

	return c.runRefreshLoop(ctx, provider, vpcIndex)
}

func (c *VPCMetadataController) fetchInitialMetadata(ctx context.Context, provider cloudtypes.Provider, vpcIndex *kube.VPCIndex) error {
	backoff := 2 * time.Second
	maxRetries := 5

	for i := 0; i < maxRetries; i++ {
		err := provider.RefreshMetadata(ctx)
		if err != nil {
			c.log.Errorf("VPC metadata refresh failed: %v", err)
			continue
		}
		metadata, err := provider.GetMetadata(ctx)
		if err == nil {
			if err := vpcIndex.Update(metadata); err != nil {
				c.log.Errorf("failed to update VPC index: %v", err)
			} else {
				c.log.Info("initial VPC metadata loaded successfully")
				return nil
			}
		}

		if i < maxRetries-1 {
			c.log.Warnf("VPC metadata fetch attempt %d/%d failed: %v, retrying in %v", i+1, maxRetries, err, backoff)
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

	c.log.Errorf("failed to fetch initial VPC metadata after %d attempts", maxRetries)
	return nil
}

func (c *VPCMetadataController) runRefreshLoop(ctx context.Context, provider cloudtypes.Provider, vpcIndex *kube.VPCIndex) error {
	ticker := time.NewTicker(c.cfg.RefreshInterval)
	defer ticker.Stop()

	c.log.Infof("starting VPC metadata refresh (interval: %v)", c.cfg.RefreshInterval)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			err := provider.RefreshMetadata(ctx)
			if err != nil {
				c.log.Errorf("VPC metadata refresh failed: %v", err)
				continue
			}

			metadata, err := provider.GetMetadata(ctx)
			if err != nil {
				c.log.Errorf("VPC metadata loading failed: %v", err)
				continue
			}

			if err := vpcIndex.Update(metadata); err != nil {
				c.log.Errorf("failed to update VPC index: %v", err)
				continue
			}

			c.log.Debug("VPC metadata refreshed successfully")
		}
	}
}
