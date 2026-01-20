package cloudprovider

import (
	"context"
	"fmt"

	"github.com/castai/kvisor/pkg/cloudprovider/gcp"
	"github.com/castai/kvisor/pkg/cloudprovider/noop"
	"github.com/castai/kvisor/pkg/cloudprovider/types"
)

// NewProvider creates a cloud provider instance based on config.
func NewProvider(ctx context.Context, cfg types.ProviderConfig) (types.Provider, error) {
	switch cfg.Type {
	case types.TypeGCP:
		return gcp.NewProvider(ctx, cfg)
	case types.TypeAWS:
		return nil, fmt.Errorf("aws provider not yet implemented")
	case types.TypeAzure:
		return nil, fmt.Errorf("azure provider not yet implemented")
	case types.TypeNone:
		return noop.NewProvider(), nil
	default:
		return nil, fmt.Errorf("unsupported cloud provider type: %s", cfg.Type)
	}
}
