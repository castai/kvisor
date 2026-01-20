package aws

import (
	"context"
	"fmt"

	"github.com/castai/kvisor/pkg/cloudprovider/types"
)

func (p *Provider) GetNetworkState(ctx context.Context) (*types.NetworkState, error) {
	return nil, fmt.Errorf("GetNetworkState not yet implemented for AWS")
}

func (p *Provider) RefreshNetworkState(ctx context.Context, network string) error {
	return fmt.Errorf("RefreshNetworkState not yet implemented for AWS")
}
