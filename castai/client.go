//go:generate mockgen -source $GOFILE -destination ./mock/client.go . Client

package castai

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/go-resty/resty/v2"
	json "github.com/json-iterator/go"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/wait"

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
	SendCISReport(ctx context.Context, report *CustomReport) error
	SendDeltaReport(ctx context.Context, report *Delta) error
	SendLinterChecks(ctx context.Context, checks []LinterCheck) error
	SendImageMetadata(ctx context.Context, meta *ImageMetadata) error
}

func NewClient(
	apiURL, apiKey string,
	log *logrus.Logger,
	clusterID string,
	binName string,
	binVersion config.SecurityAgentVersion,
) Client {

	httpClient := newDefaultDeltaHTTPClient()
	restClient := resty.NewWithClient(httpClient)
	restClient.SetBaseURL(apiURL)
	restClient.Header.Set(headerAPIKey, apiKey)
	restClient.Header.Set(headerUserAgent, binName+"/"+binVersion.Version)
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
	binVersion config.SecurityAgentVersion
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

func (c *client) SendDeltaReport(ctx context.Context, report *Delta) error {
	return c.sendReport(ctx, report, "delta")
}

func (c *client) SendCISReport(ctx context.Context, report *CustomReport) error {
	return c.sendReport(ctx, report, "cis-report")
}

func (c *client) SendLinterChecks(ctx context.Context, checks []LinterCheck) error {
	return c.sendReport(ctx, checks, "linter-checks")
}

func (c *client) SendImageMetadata(ctx context.Context, meta *ImageMetadata) error {
	return c.sendReport(ctx, meta, "image-metadata")
}

func (c *client) sendReport(ctx context.Context, report any, reportType string) error {
	uri, err := url.Parse(fmt.Sprintf("%s/v1/security/insights/agent/%s/%s", c.apiURL, c.clusterID, reportType))
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

		if err := json.NewEncoder(gzipWriter).Encode(report); err != nil {
			c.log.Errorf("compressing json: %v", err)
		}
	}()

	ctx, cancel := context.WithTimeout(ctx, totalSendDeltaTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri.String(), pipeReader)
	if err != nil {
		return fmt.Errorf("creating request for report type %s: %w", reportType, err)
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
			c.log.Warnf("failed sending request for report %s: %v", reportType, err)
			return false, fmt.Errorf("sending request %s: %w", reportType, err)
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
		return fmt.Errorf("%s request error status_code=%d body=%s url=%s", reportType, resp.StatusCode, buf.String(), uri.String())
	}

	return nil
}
