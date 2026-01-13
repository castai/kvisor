package cloudprovider

import (
	"context"

	"github.com/castai/kvisor/pkg/cloudprovider/types"
)

// noOpProvider is a provider implementation that does nothing.
type noOpProvider struct{}

func (n *noOpProvider) GetMetadata(ctx context.Context) (*types.Metadata, error) {
	return &types.Metadata{
		Provider: types.TypeNone,
	}, nil
}

func (n *noOpProvider) RefreshMetadata(ctx context.Context) error {
	return nil
}

func (n *noOpProvider) Type() types.Type {
	return types.TypeNone
}

func (n *noOpProvider) Close() error {
	return nil
}
