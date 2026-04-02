package gpu

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

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
	httpClient *http.Client
	cfg        CastAIClientConfig
	log        *logging.Logger
}

func NewCastAIClient(cfg CastAIClientConfig, log *logging.Logger) CastAIClient {
	return &castaiClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		cfg:        cfg,
		log:        log,
	}
}

func (c *castaiClient) UploadBatch(ctx context.Context, batch *pb.MetricsBatch) error {
	buf, err := c.toBuffer(batch)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/kubernetes/clusters/%s/gpu-metrics", c.cfg.APIURL, c.cfg.ClusterID)

	return wait.ExponentialBackoffWithContext(ctx, castaiBackoff, func(ctx context.Context) (bool, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf.Bytes()))
		if err != nil {
			return false, fmt.Errorf("creating request: %w", err)
		}
		req.Header.Set(castaiTokenHeader, c.cfg.APIKey)
		req.Header.Set("Content-Type", "application/protobuf")
		req.Header.Set("Content-Encoding", "gzip")
		req.Header.Set("User-Agent", fmt.Sprintf("castai-kvisor-gpu/%s", c.cfg.Version))

		resp, err := c.httpClient.Do(req)
		if err != nil {
			c.log.WithField("error", err.Error()).Error("error making http request to gpu-metrics endpoint")
			return false, nil
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)

		switch {
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			return true, nil
		case resp.StatusCode >= 400 && resp.StatusCode < 500:
			return true, fmt.Errorf("gpu-metrics upload failed: status code: %d, status: %s", resp.StatusCode, resp.Status)
		default:
			c.log.Errorf("gpu-metrics upload server error: status code: %d, status: %s", resp.StatusCode, resp.Status)
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
