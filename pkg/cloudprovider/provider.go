package cloudprovider

import (
	"context"
	"errors"
	"fmt"

	"github.com/castai/kvisor/pkg/cloudprovider/aws"
	"github.com/castai/kvisor/pkg/cloudprovider/gcp"
	"github.com/castai/kvisor/pkg/cloudprovider/types"
)

// TODO(samu): Remove when all providers are implemented
var ErrProviderNotImplemented = errors.New("provider not implemented yet")

// NewProvider creates a cloud provider instance based on config.
func NewProvider(ctx context.Context, cfg types.ProviderConfig) (types.Provider, error) {
	switch cfg.Type {
	case types.TypeGCP:
		return gcp.NewProvider(ctx, cfg)
	case types.TypeAWS:
		return aws.NewProvider(ctx, cfg)
	case types.TypeAzure:
		return nil, fmt.Errorf("azure: %w", ErrProviderNotImplemented)
	default:
		return nil, fmt.Errorf("unsupported cloud provider type: %s", cfg.Type)
	}
}

func DomainToProviderType(domain string) string {
	switch domain {
	case types.DomainGCP:
		return string(types.TypeGCP)
	case types.DomainAWS:
		return string(types.TypeAWS)
	default:
		return ""
	}
}
