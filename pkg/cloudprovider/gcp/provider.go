package gcp

import (
	"context"
	"fmt"
	"sync"

	compute "cloud.google.com/go/compute/apiv1"
	"github.com/castai/kvisor/pkg/cloudprovider/types"
	"github.com/castai/kvisor/pkg/logging"
)

type Provider struct {
	log *logging.Logger
	cfg types.Config

	// GCP clients
	networksClient    *compute.NetworksClient
	subnetworksClient *compute.SubnetworksClient

	// Cached metadata
	mu       sync.RWMutex
	metadata *types.Metadata
}

// NewProvider creates a new GCP provider instance.
func NewProvider(ctx context.Context, cfg types.Config) (types.Provider, error) {
	log := logging.New(&logging.Config{}).
		WithField("component", "vpc_metadata").
		WithField("cloudprovider", "gcp")

	// Build client options with authentication
	clientOptions, err := buildClientOptions(cfg)
	if err != nil {
		return nil, fmt.Errorf("building GCP client options: %w", err)
	}

	networksClient, err := compute.NewNetworksRESTClient(ctx, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("creating networks client: %w", err)
	}

	subnetworksClient, err := compute.NewSubnetworksRESTClient(ctx, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("creating subnetworks client: %w", err)
	}

	p := &Provider{
		log:               log,
		cfg:               cfg,
		networksClient:    networksClient,
		subnetworksClient: subnetworksClient,
	}

	log.With("project", cfg.GCPProjectID).Info("GCP network provider initialized")

	return p, nil
}

func (p *Provider) GetMetadata(ctx context.Context) (*types.Metadata, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.metadata == nil {
		return nil, fmt.Errorf("metadata not yet available")
	}

	return p.metadata, nil
}

func (p *Provider) Type() types.Type {
	return types.TypeGCP
}

func (p *Provider) Close() error {
	var errs []error
	if p.networksClient != nil {
		if err := p.networksClient.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing networks client: %w", err))
		}
	}
	if p.subnetworksClient != nil {
		if err := p.subnetworksClient.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing subnetworks client: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors closing GCP provider: %v", errs)
	}

	return nil
}
