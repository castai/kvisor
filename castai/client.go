package castai

import (
	"context"
	"fmt"
	"net/http"
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
	client.SetHostURL(url)
	client.SetTimeout(5 * time.Minute) // Hard timeout for any request.
	client.Header.Set(http.CanonicalHeaderKey(headerAPIKey), key)
	client.Header.Set(http.CanonicalHeaderKey(headerUserAgent), "castai-sec-agent/"+binVersion.Version)
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
		Post(fmt.Sprintf("/v1/security/insights/%s/logs", c.clusterID))

	if err != nil {
		return fmt.Errorf("sending logs: %w", err)
	}
	if resp.IsError() {
		return fmt.Errorf("sending logs: request error status_code=%d body=%s", resp.StatusCode(), resp.Body())
	}

	return nil
}

type LogEvent struct {
	Level   string        `json:"level"`
	Time    time.Time     `json:"time"`
	Message string        `json:"message"`
	Fields  logrus.Fields `json:"fields"`
}
