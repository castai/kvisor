package blobscache

import (
	"context"
	"errors"
	"fmt"
	"net"
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

	srv := NewBlobsCacheServer(log, ServerConfig{})
	listener, err := newLocalListener()
	r.NoError(err)
	srv.listener = listener
	go srv.Start(ctx)

	client := NewRemoteBlobsCache(fmt.Sprintf("http://%s", listener.Addr().String()))

	// Wait unti server is ready
	r.Eventually(func() bool {
		_, err := client.GetBlob(ctx, "noop")
		return errors.Is(err, ErrCacheNotFound)
	}, 3*time.Second, 10*time.Millisecond)

	blob := []byte(`{"some": "json"}`)
	err = client.PutBlob(ctx, "b1", blob)
	r.NoError(err)

	addedBlob, err := client.GetBlob(ctx, "b1")
	r.NoError(err)
	r.Equal(blob, addedBlob)
}

func newLocalListener() (net.Listener, error) {
	return net.Listen("tcp", "127.0.0.1:0")
}
