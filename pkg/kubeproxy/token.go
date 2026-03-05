package kubeproxy

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type TokenCreatorFunc func(ctx context.Context) (token string, expiresAt time.Time, err error)

type TokenProviderConfig struct {
	CreateToken TokenCreatorFunc
}

type TokenProvider struct {
	createToken TokenCreatorFunc
	mu          sync.RWMutex
	token       string
	expiresAt   time.Time
}

func NewTokenProvider(cfg TokenProviderConfig) *TokenProvider {
	return &TokenProvider{createToken: cfg.CreateToken}
}

func (tp *TokenProvider) isValid() bool {
	return tp.token != "" && time.Now().Before(tp.expiresAt)
}

func (tp *TokenProvider) GetToken(ctx context.Context) (string, error) {
	tp.mu.RLock()
	if tp.isValid() {
		token := tp.token
		tp.mu.RUnlock()
		return token, nil
	}
	tp.mu.RUnlock()
	return tp.refreshToken(ctx)
}

func (tp *TokenProvider) refreshToken(ctx context.Context) (string, error) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	if tp.isValid() {
		return tp.token, nil
	}
	token, expiresAt, err := tp.createToken(ctx)
	if err != nil {
		return "", err
	}
	tp.token = token
	ttl := time.Until(expiresAt)
	tp.expiresAt = expiresAt.Add(-ttl / 2)
	return token, nil
}

type tokenRoundTripper struct {
	tp   *TokenProvider
	base http.RoundTripper
}

func NewTokenRoundTripper(tp *TokenProvider, base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &tokenRoundTripper{tp: tp, base: base}
}

func (t *tokenRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := t.tp.GetToken(req.Context())
	if err != nil {
		return nil, fmt.Errorf("getting token: %w", err)
	}
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+token)
	return t.base.RoundTrip(req)
}
