package cri

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCriClientUseSocketEvenWithHTTPProxy(t *testing.T) {
	os.Setenv("HTTPS_PROXY", "http://127.0.0.1")

	r := require.New(t)
	_, _, err := NewRuntimeClient(context.Background(), "unix:///no-such-dir/containerd/containerd.sock")
	r.ErrorContains(err, "no such file or directory")
}
