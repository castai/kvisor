package blobscache

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestBlobsCacheServer(t *testing.T) {
	r := require.New(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	srv := NewServer(log, ServerConfig{})
	mux := http.NewServeMux()
	srv.RegisterHandlers(mux)
	httpSrv := httptest.NewServer(mux)
	defer httpSrv.Close()

	client := NewRemoteBlobsCacheClient(httpSrv.URL)

	// Wait unti server is ready.
	r.Eventually(func() bool {
		_, err := client.GetBlob(ctx, "noop")
		return errors.Is(err, ErrCacheNotFound)
	}, 3*time.Second, 10*time.Millisecond)

	blob := []byte(`{"some": "json"}`)
	err := client.PutBlob(ctx, "b1", blob)
	r.NoError(err)

	addedBlob, err := client.GetBlob(ctx, "b1")
	r.NoError(err)
	r.Equal(blob, addedBlob)
}
