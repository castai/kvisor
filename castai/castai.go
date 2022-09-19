//go:generate mockgen -source $GOFILE -destination ./mock/client.go . Client

package castai

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/sirupsen/logrus"

	"github.com/castai/sec-agent/config"
)

const (
	headerAPIKey            = "X-API-Key"
	headerUserAgent         = "User-Agent"
	headerKubernetesVersion = "X-K8s-Version"
)

type Client interface {
	SendLogs(ctx context.Context, req *LogEvent) error
	SendCISReport(ctx context.Context, report []byte) error
}

func NewClient(log *logrus.Logger, rest *resty.Client, clusterID string) Client {
	return &client{
		log:       log,
		rest:      rest,
		clusterID: clusterID,
	}
}

// NewDefaultClient configures a default instance of the resty.Client used to do HTTP requests.
func NewDefaultClient(url, key string, level logrus.Level, binVersion *config.SecurityAgentVersion) *resty.Client {
	client := resty.New()
	client.SetBaseURL(url)
	client.SetTimeout(5 * time.Minute) // Hard timeout for any request.
	client.Header.Set(headerAPIKey, key)
	client.Header.Set(headerUserAgent, "castai-sec-agent/"+binVersion.Version)
	if level == logrus.TraceLevel {
		client.SetDebug(true)
	}

	return client
}

type client struct {
	log       *logrus.Logger
	rest      *resty.Client
	clusterID string
}

func (c *client) SendLogs(ctx context.Context, req *LogEvent) error {
	resp, err := c.rest.R().
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

func (c *client) SendCISReport(ctx context.Context, report []byte) error {
	pipeReader, pipeWriter := io.Pipe()

	go func() {
		defer pipeWriter.Close()

		gzipWriter := gzip.NewWriter(pipeWriter)
		defer gzipWriter.Close()

		_, err := gzipWriter.Write(report)
		if err != nil {
			c.log.Errorf("compressing report: %v", err)
		}
	}()

	resp, err := c.rest.R().
		SetBody(pipeReader).
		SetHeader("Content-Encoding", "gzip").
		SetContext(ctx).
		Post(fmt.Sprintf("/v1/security/insights/cis/%s/submit", c.clusterID))

	if err != nil {
		return fmt.Errorf("sending report: %w", err)
	}
	if resp.IsError() {
		return fmt.Errorf("sending report: request error status_code=%d body=%s", resp.StatusCode(), resp.Body())
	}

	return nil
}

type LogEvent struct {
	Level   string        `json:"level"`
	Time    time.Time     `json:"time"`
	Message string        `json:"message"`
	Fields  logrus.Fields `json:"fields"`
}
