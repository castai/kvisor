package mock

import (
	"context"

	"github.com/castai/kvisor/blobscache"
)

type MockClient struct{}

func (m MockClient) PutBlob(ctx context.Context, key string, blob []byte) error {
	return nil
}

func (m MockClient) GetBlob(ctx context.Context, key string) ([]byte, error) {
	return nil, blobscache.ErrCacheNotFound
}
