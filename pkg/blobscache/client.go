package blobscache

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	ia "github.com/castai/image-analyzer"
	json "github.com/json-iterator/go"
)

func NewRemoteBlobsCacheClient(serverURL string) ia.CacheClient {
	return &remoteBlobsCache{
		url: serverURL,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

type remoteBlobsCache struct {
	url    string
	client *http.Client
}

func (c *remoteBlobsCache) PutBlob(ctx context.Context, key string, blob []byte) error {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(&PubBlobRequest{
		Key:  key,
		Blob: blob,
	}); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/blobscache/PutBlob", c.url), &buf)
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if st := resp.StatusCode; st != http.StatusOK {
		errMsg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("put blob failed, response status=%d: %v", st, string(errMsg))
	}
	return nil
}

func (c *remoteBlobsCache) GetBlob(ctx context.Context, key string) ([]byte, error) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(&GetBlobRequest{
		Key: key,
	}); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/blobscache/GetBlob", c.url), &buf)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if st := resp.StatusCode; st != http.StatusOK {
		if st == http.StatusNotFound {
			return nil, ia.ErrCacheNotFound
		}
		errMsg, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("put blob failed, response status=%d: %v", st, string(errMsg))
	}

	var res GetBlobResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}
	return res.Blob, nil
}

func NewMockBlobsCacheClient() ia.CacheClient {
	return &mockBlobsCacheClient{}
}

type mockBlobsCacheClient struct {
}

func (m mockBlobsCacheClient) PutBlob(ctx context.Context, key string, blob []byte) error {
	return nil
}

func (m mockBlobsCacheClient) GetBlob(ctx context.Context, key string) ([]byte, error) {
	return nil, ia.ErrCacheNotFound
}
