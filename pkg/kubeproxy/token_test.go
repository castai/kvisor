package kubeproxy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTokenProvider_GetToken(t *testing.T) {
	t.Run("requests and caches token", func(t *testing.T) {
		callCount := 0
		tp := NewTokenProvider(TokenProviderConfig{
			CreateToken: func(ctx context.Context) (string, time.Time, error) {
				callCount++
				return "restricted-token-123", time.Now().Add(15 * time.Minute), nil
			},
		})

		ctx := context.Background()

		token, err := tp.GetToken(ctx)
		require.NoError(t, err)
		require.Equal(t, "restricted-token-123", token)
		require.Equal(t, 1, callCount)

		token2, err := tp.GetToken(ctx)
		require.NoError(t, err)
		require.Equal(t, "restricted-token-123", token2)
		require.Equal(t, 1, callCount, "second call should use cache")
	})

	t.Run("refreshes expired token", func(t *testing.T) {
		callCount := 0
		tp := NewTokenProvider(TokenProviderConfig{
			CreateToken: func(ctx context.Context) (string, time.Time, error) {
				callCount++
				return fmt.Sprintf("token-%d", callCount), time.Now().Add(15 * time.Minute), nil
			},
		})

		ctx := context.Background()

		_, err := tp.GetToken(ctx)
		require.NoError(t, err)
		require.Equal(t, 1, callCount)

		tp.mu.Lock()
		tp.expiresAt = time.Now().Add(-1 * time.Minute)
		tp.mu.Unlock()

		_, err = tp.GetToken(ctx)
		require.NoError(t, err)
		require.Equal(t, 2, callCount, "should refresh expired token")
	})

	t.Run("returns error on CreateToken failure", func(t *testing.T) {
		tp := NewTokenProvider(TokenProviderConfig{
			CreateToken: func(ctx context.Context) (string, time.Time, error) {
				return "", time.Time{}, fmt.Errorf("token request returned status 403: forbidden")
			},
		})

		_, err := tp.GetToken(context.Background())
		require.Error(t, err)
		require.Contains(t, err.Error(), "403")
	})
}

func TestTokenRoundTripper(t *testing.T) {
	tp := NewTokenProvider(TokenProviderConfig{
		CreateToken: func(ctx context.Context) (string, time.Time, error) {
			return "injected-token", time.Now().Add(15 * time.Minute), nil
		},
	})

	var capturedAuth string
	backendSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer backendSrv.Close()

	rt := NewTokenRoundTripper(tp, backendSrv.Client().Transport)
	client := &http.Client{Transport: rt}

	req, _ := http.NewRequest(http.MethodGet, backendSrv.URL+"/api/v1/pods", nil)
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "Bearer injected-token", capturedAuth)
}
