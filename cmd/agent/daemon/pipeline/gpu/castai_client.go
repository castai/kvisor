package gpu

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/go-resty/resty/v2"
	"google.golang.org/protobuf/proto"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/castai/kvisor/cmd/agent/daemon/pipeline/gpu/pb"
	"github.com/castai/logging"
)

const (
	castaiTokenHeader = "X-API-Key" // #nosec G101

	castaiRetryCount = 5
)

var castaiBackoff = wait.Backoff{
	Steps:    castaiRetryCount,
	Duration: 50 * time.Millisecond,
	Factor:   8,
	Jitter:   0.15,
}

// CastAIClient sends GPU metric batches to the CAST AI REST API.
type CastAIClient interface {
	UploadBatch(ctx context.Context, batch *pb.MetricsBatch) error
}

// CastAIClientConfig holds the connection parameters for the CAST AI GPU metrics endpoint.
type CastAIClientConfig struct {
	APIURL    string
	APIKey    string // nolint:gosec // G117: false positive
	ClusterID string
	Version   string
}

type castaiClient struct {
	restyClient *resty.Client
	cfg         CastAIClientConfig
	log         *logging.Logger
}

func NewCastAIClient(cfg CastAIClientConfig, log *logging.Logger) CastAIClient {
	r := resty.New()
	r.BaseURL = cfg.APIURL
	r.SetHeaders(map[string]string{
		castaiTokenHeader:                         cfg.APIKey,
		http.CanonicalHeaderKey("Content-Type"):   "application/protobuf",
		http.CanonicalHeaderKey("Content-Encoding"): "gzip",
		http.CanonicalHeaderKey("User-Agent"):     fmt.Sprintf("castai-kvisor-gpu/%s", cfg.Version),
	})

	return &castaiClient{
		restyClient: r,
		cfg:         cfg,
		log:         log,
	}
}

func (c *castaiClient) UploadBatch(ctx context.Context, batch *pb.MetricsBatch) error {
	buf, err := c.toBuffer(batch)
	if err != nil {
		return err
	}

	return wait.ExponentialBackoffWithContext(ctx, castaiBackoff, func(ctx context.Context) (bool, error) {
		resp, err := c.restyClient.R().
			SetContext(ctx).
			SetBody(buf.Bytes()).
			Post(fmt.Sprintf("/v1/kubernetes/clusters/%s/gpu-metrics", c.cfg.ClusterID))

		if err != nil {
			c.log.WithField("error", err.Error()).Error("error making http request to gpu-metrics endpoint")
			return false, nil
		}

		statusCode := resp.StatusCode()
		switch {
		case statusCode >= 200 && statusCode < 300:
			return true, nil
		case statusCode >= 400 && statusCode < 500:
			return true, fmt.Errorf("gpu-metrics upload failed: status code: %d, status: %s", statusCode, resp.Status())
		default:
			c.log.Errorf("gpu-metrics upload server error: status code: %d, status: %s", statusCode, resp.Status())
			return false, nil
		}
	})
}

func (c *castaiClient) toBuffer(batch *pb.MetricsBatch) (*bytes.Buffer, error) {
	payload := new(bytes.Buffer)

	protoBytes, err := proto.Marshal(batch)
	if err != nil {
		return nil, fmt.Errorf("error marshaling batch: %w", err)
	}

	writer := gzip.NewWriter(payload)
	if _, err := writer.Write(protoBytes); err != nil {
		return nil, fmt.Errorf("error compressing payload: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("error closing gzip writer: %w", err)
	}

	return payload, nil
}
