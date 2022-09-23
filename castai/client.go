//go:generate mockgen -source $GOFILE -destination ./mock/client.go . Client

package castai

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/castai/sec-agent/castai/contract"
	"github.com/castai/sec-agent/config"
)

const (
	headerAPIKey            = "X-API-Key"
	headerUserAgent         = "User-Agent"
	headerContentType       = "Content-Type"
	headerContentEncoding   = "Content-Encoding"
	headerKubernetesVersion = "X-K8s-Version"
	totalSendDeltaTimeout   = 2 * time.Minute
)

type Client interface {
	SendLogs(ctx context.Context, req *LogEvent) error
	SendDelta(ctx context.Context, delta *Delta) error
	SendLinterChecks(ctx context.Context, checks []contract.LinterCheck) error
}

func NewClient(
	apiURL, apiKey string,
	log *logrus.Logger,
	clusterID string,
	binVersion *config.SecurityAgentVersion,
) Client {

	httpClient := newDefaultDeltaHTTPClient()
	restClient := resty.NewWithClient(httpClient)
	restClient.SetBaseURL(apiURL)
	restClient.Header.Set(headerAPIKey, apiKey)
	restClient.Header.Set(headerUserAgent, "castai-sec-agent/"+binVersion.Version)
	if log.Level == logrus.TraceLevel {
		restClient.SetDebug(true)
	}

	return &client{
		apiURL:     apiURL,
		apiKey:     apiKey,
		log:        log,
		restClient: restClient,
		httpClient: httpClient,
		clusterID:  clusterID,
		binVersion: binVersion,
	}
}

func createHTTPTransport() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

func newDefaultDeltaHTTPClient() *http.Client {
	return &http.Client{
		Timeout:   2 * time.Minute,
		Transport: createHTTPTransport(),
	}
}

type client struct {
	apiURL     string
	apiKey     string
	log        *logrus.Logger
	restClient *resty.Client
	httpClient *http.Client
	clusterID  string
	binVersion *config.SecurityAgentVersion
}

func (c *client) SendLogs(ctx context.Context, req *LogEvent) error {
	resp, err := c.restClient.R().
		SetBody(req).
		SetContext(ctx).
		Post(fmt.Sprintf("/v1/security/insights/%s/log", c.clusterID))

	if err != nil {
		return fmt.Errorf("sending logs: %w", err)
	}
	if resp.IsError() {
		return fmt.Errorf("sending logs: request error status_code=%d body=%s", resp.StatusCode(), resp.Body())
	}

	return nil
}

func (c *client) SendDelta(ctx context.Context, delta *Delta) error {
	uri, err := url.Parse(fmt.Sprintf("%s/v1/security/insights/agent/%s/delta", c.apiURL, c.clusterID))
	if err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}

	pipeReader, pipeWriter := io.Pipe()

	go func() {
		defer func() {
			if err := pipeWriter.Close(); err != nil {
				c.log.Errorf("closing gzip pipe: %v", err)
			}
		}()

		gzipWriter := gzip.NewWriter(pipeWriter)
		defer func() {
			if err := gzipWriter.Close(); err != nil {
				c.log.Errorf("closing gzip writer: %v", err)
			}
		}()

		if err := json.NewEncoder(gzipWriter).Encode(delta); err != nil {
			c.log.Errorf("compressing json: %v", err)
		}
	}()

	ctx, cancel := context.WithTimeout(ctx, totalSendDeltaTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri.String(), pipeReader)
	if err != nil {
		return fmt.Errorf("creating delta request: %w", err)
	}

	req.Header.Set(headerContentType, "application/json")
	req.Header.Set(headerContentEncoding, "gzip")
	req.Header.Set(headerAPIKey, c.apiKey)
	req.Header.Set(headerUserAgent, "castai-sec-agent/"+c.binVersion.Version)

	var resp *http.Response

	backoff := wait.Backoff{
		Duration: 10 * time.Millisecond,
		Factor:   1.5,
		Jitter:   0.2,
		Steps:    3,
	}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func() (done bool, err error) {
		resp, err = c.httpClient.Do(req)
		if err != nil {
			c.log.Warnf("failed sending delta request: %v", err)
			return false, fmt.Errorf("sending delta request: %w", err)
		}
		return true, nil
	})
	if err != nil {
		return err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			c.log.Errorf("closing response body: %v", err)
		}
	}()

	if resp.StatusCode > 399 {
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(resp.Body); err != nil {
			c.log.Errorf("failed reading error response body: %v", err)
		}
		return fmt.Errorf("delta request error status_code=%d body=%s url=%s", resp.StatusCode, buf.String(), uri.String())
	}

	return nil
}

func (c *client) SendLinterChecks(ctx context.Context, checks []contract.LinterCheck) error {
	var buffer bytes.Buffer
	if err := json.NewEncoder(&buffer).Encode(checks); err != nil {
		return err
	}

	pipeReader, pipeWriter := io.Pipe()

	go func() {
		defer pipeWriter.Close()

		gzipWriter := gzip.NewWriter(pipeWriter)
		defer gzipWriter.Close()

		_, err := gzipWriter.Write(buffer.Bytes())
		if err != nil {
			c.log.Errorf("compressing checks: %v", err)
		}
	}()

	resp, err := c.restClient.R().
		SetBody(pipeReader).
		SetHeader("Content-Type", "application/json").
		SetContext(ctx).
		Post(fmt.Sprintf("/v1/security/insights/agent/%s/linter-checks", c.clusterID))
	if err != nil {
		return fmt.Errorf("sending checks: %w", err)
	}
	if resp.IsError() {
		return fmt.Errorf("sending checks: request error status_code=%d body=%s", resp.StatusCode(), resp.Body())
	}

	return nil
}

type LogEvent struct {
	Level   string        `json:"level"`
	Time    time.Time     `json:"time"`
	Message string        `json:"message"`
	Fields  logrus.Fields `json:"fields"`
}

type Delta struct {
	FullSnapshot bool        `json:"full_snapshot,omitempty"`
	Items        []DeltaItem `json:"items"`
}

type DeltaItem struct {
	Event            EventType `json:"event"`
	ObjectUID        string    `json:"object_uid"`
	ObjectName       string    `json:"object_name,omitempty"`
	ObjectNamespace  string    `json:"object_namespace,omitempty"`
	ObjectKind       string    `json:"object_kind,omitempty"`
	ObjectAPIVersion string    `json:"object_api_version,omitempty"`
	ObjectCreatedAt  time.Time `json:"object_created_at,omitempty"`
}

type EventType string

const (
	EventAdd    EventType = "add"
	EventUpdate EventType = "update"
	EventDelete EventType = "delete"
)
