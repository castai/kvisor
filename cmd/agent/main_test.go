package main

import (
	"errors"
	"net/http"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestKubeRetryTransport(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	t.Run("retry connection refused error", func(t *testing.T) {
		r := require.New(t)

		next := &mockRoundTripper{
			err: syscall.ECONNREFUSED,
		}
		rt := kubeRetryTransport{
			log:           log,
			next:          next,
			maxRetries:    3,
			retryInterval: 100 * time.Millisecond,
		}
		_, err := rt.RoundTrip(nil) //nolint:bodyclose
		r.EqualError(err, "connection refused")
		r.Equal(int32(4), next.calls)
	})

	t.Run("do not retry non connection refused errors", func(t *testing.T) {
		r := require.New(t)

		next := &mockRoundTripper{
			err: errors.New("ups"),
		}
		rt := kubeRetryTransport{
			log:           log,
			next:          next,
			maxRetries:    3,
			retryInterval: 100 * time.Millisecond,
		}
		_, err := rt.RoundTrip(nil) //nolint:bodyclose
		r.EqualError(err, "ups")
		r.Equal(int32(1), next.calls)
	})
}

type mockRoundTripper struct {
	err   error
	calls int32
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	atomic.AddInt32(&m.calls, 1)
	return nil, m.err
}
