package gcp

import (
	"context"
	"errors"
	"fmt"
	"sync"

	compute "cloud.google.com/go/compute/apiv1"

	"github.com/castai/kvisor/pkg/cloudprovider/types"
	"github.com/castai/logging"
)

type Provider struct {
	log *logging.Logger
	cfg types.ProviderConfig

	// GCP clients
	networksClient    *compute.NetworksClient
	subnetworksClient *compute.SubnetworksClient
	disksClient       *compute.DisksClient
	instancesClient   *compute.InstancesClient

	// Cached network state
	networkStateMu sync.RWMutex
	networkState   *types.NetworkState
}

// NewProvider creates a new GCP provider instance.
func NewProvider(ctx context.Context, log *logging.Logger, cfg types.ProviderConfig) (types.Provider, error) {
	log = log.WithField("cloudprovider", "gcp")

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

	disksClient, err := compute.NewDisksRESTClient(ctx, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("creating disks client: %w", err)
	}

	instancesClient, err := compute.NewInstancesRESTClient(ctx, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("creating instances client: %w", err)
	}

	p := &Provider{
		log:               log,
		cfg:               cfg,
		networksClient:    networksClient,
		subnetworksClient: subnetworksClient,
		disksClient:       disksClient,
		instancesClient:   instancesClient,
	}

	log.With("project", cfg.GCPProjectID).Info("gcp provider initialized")

	return p, nil
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
	if p.disksClient != nil {
		if err := p.disksClient.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing disks client: %w", err))
		}
	}
	if p.instancesClient != nil {
		if err := p.instancesClient.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing instancesClient client: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors closing GCP provider: %w", errors.Join(errs...))
	}
	return nil
}
