package gcp

import (
	"context"
	"fmt"

	"github.com/castai/kvisor/pkg/cloudprovider/types"
)

func (p *Provider) GetStorageState(ctx context.Context, instanceIds ...string) (*types.StorageState, error) {
	return nil, fmt.Errorf("GetStorageState not yet implemented for GCP")
}
