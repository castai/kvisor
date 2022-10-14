package blobscache

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	json "github.com/json-iterator/go"
)

var (
	ErrCacheNotFound = errors.New("cache not found")
)

type Client interface {
	PutBlob(ctx context.Context, key string, blob []byte) error
	GetBlob(ctx context.Context, key string) ([]byte, error)
}

func NewRemoteBlobsCache(url string) Client {
	return &remoteBlobsCache{
		url: url,
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
	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/PutBlob", c.url), &buf)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if st := resp.StatusCode; st != http.StatusOK {
		return fmt.Errorf("put blob failed, response status=%d", st)
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
	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/GetBlob", c.url), &buf)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if st := resp.StatusCode; st != http.StatusOK {
		if st == http.StatusNotFound {
			return nil, ErrCacheNotFound
		}
		return nil, fmt.Errorf("put blob failed, response status=%d", st)
	}

	var res GetBlobResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}
	return res.Blob, nil
}
