package cloudprovider

import (
	"context"
	"fmt"

	"github.com/castai/kvisor/pkg/cloudprovider/gcp"
	"github.com/castai/kvisor/pkg/cloudprovider/types"
)

// NewProvider creates a cloud provider instance based on config.
func NewProvider(ctx context.Context, cfg types.Config) (types.Provider, error) {
	switch cfg.Type {
	case types.TypeGCP:
		return gcp.NewProvider(ctx, cfg)
	case types.TypeAWS:
		return nil, fmt.Errorf("AWS provider not yet implemented")
	case types.TypeAzure:
		return nil, fmt.Errorf("Azure provider not yet implemented")
	case types.TypeNone:
		return NewNoOpProvider(), nil
	default:
		return nil, fmt.Errorf("unsupported cloud provider type: %s", cfg.Type)
	}
}

// NewNoOpProvider returns a provider that does nothing.
func NewNoOpProvider() types.Provider {
	return &noOpProvider{}
}
