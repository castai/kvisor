package blobscache

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"

	ia "github.com/castai/image-analyzer"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

func TestBlobsCacheServer(t *testing.T) {
	r := require.New(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log := logging.New(&logging.Config{Level: slog.LevelDebug})

	srv := NewServer(log)
	e := echo.New()
	srv.RegisterHandlers(e)
	httpSrv := httptest.NewServer(e)
	defer httpSrv.Close()

	client := NewRemoteBlobsCacheClient(httpSrv.URL)

	// Wait unti server is ready.
	r.Eventually(func() bool {
		_, err := client.GetBlob(ctx, "noop")
		fmt.Println(err)
		return errors.Is(err, ia.ErrCacheNotFound)
	}, 3*time.Second, 10*time.Millisecond)

	blob := []byte(`{"some":"json"}`)
	err := client.PutBlob(ctx, "b1", blob)
	r.NoError(err)

	addedBlob, err := client.GetBlob(ctx, "b1")
	r.NoError(err)
	r.Equal(string(blob), string(addedBlob))
}
