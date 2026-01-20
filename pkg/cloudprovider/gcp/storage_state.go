package gcp

import (
	"context"
	"fmt"

	"github.com/castai/kvisor/pkg/cloudprovider/types"
)

func (p *Provider) GetStorageState(ctx context.Context) (*types.StorageState, error) {
	return nil, fmt.Errorf("GetStorageState not yet implemented for GCP")
}

func (p *Provider) RefreshStorageState(ctx context.Context, instanceIds ...string) error {
	return fmt.Errorf("RefreshNetworkState not yet implemented for GCP")
}
