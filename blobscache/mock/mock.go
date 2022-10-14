package mock

import (
	"context"
	"github.com/davecgh/go-spew/spew"

	"github.com/castai/sec-agent/blobscache"
)

type MockClient struct{}

func (m MockClient) PutBlob(ctx context.Context, key string, blob []byte) error {
	spew.Dump(blob)
	return nil
}

func (m MockClient) GetBlob(ctx context.Context, key string) ([]byte, error) {
	return nil, blobscache.ErrCacheNotFound
}
