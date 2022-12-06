package gke

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

func newMetadataTokenSource() oauth2.TokenSource {
	return &metadataTokenSource{
		httpClient: &http.Client{Timeout: 3 * time.Second},
	}
}

type metadataTokenSource struct {
	httpClient *http.Client
}

func (m *metadataTokenSource) Token() (*oauth2.Token, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Metadata-Flavor", "Google")
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("received %d status code: %s", resp.StatusCode, string(msg))
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var tkn oauth2.Token
	if err := json.Unmarshal(raw, &tkn); err != nil {
		return nil, err
	}
	return &tkn, nil
}
