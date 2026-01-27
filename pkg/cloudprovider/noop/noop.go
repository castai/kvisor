package noop

import (
	"context"

	"github.com/castai/kvisor/pkg/cloudprovider/types"
)

type noOpProvider struct{}

// NewProvider returns a provider that does nothing
func NewProvider() types.Provider {
	return &noOpProvider{}
}

func (n *noOpProvider) Type() types.Type {
	return types.Type("noop")
}

func (n *noOpProvider) GetNetworkState(ctx context.Context) (*types.NetworkState, error) {
	return nil, nil
}

func (n *noOpProvider) RefreshNetworkState(ctx context.Context, network string) error {
	return nil
}

func (n *noOpProvider) GetStorageState(ctx context.Context, instanceIds ...string) (*types.StorageState, error) {
	return nil, nil
}

func (n *noOpProvider) Close() error {
	return nil
}
