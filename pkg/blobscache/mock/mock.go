package mock

import (
	"context"

	ia "github.com/castai/image-analyzer"
)

type MockClient struct{}

func (m MockClient) PutBlob(ctx context.Context, key string, blob []byte) error {
	return nil
}

func (m MockClient) GetBlob(ctx context.Context, key string) ([]byte, error) {
	return nil, ia.ErrCacheNotFound
}
