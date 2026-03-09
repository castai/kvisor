package clusterproxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v5"

	proxypb "github.com/castai/kvisor/api/v1/proxy"
	"github.com/castai/logging"
)

const (
	maxConcurrentRequests = 50
	maxResponseChunkSize  = 32 * 1024
	sendResponseTimeout   = 30 * time.Second
)

var allowedResponseHeaders = map[string]bool{
	"Audit-Id":                          true,
	"Content-Type":                      true,
	"Content-Length":                    true,
	"Content-Encoding":                  true,
	"Cache-Control":                     true,
	"Date":                              true,
	"X-Kubernetes-Pf-Flowschema-Uid":    true,
	"X-Kubernetes-Pf-Prioritylevel-Uid": true,
}

var allowedRequestHeaders = map[string]bool{
	"accept":          true,
	"accept-encoding": true,
	"content-type":    true,
	"content-length":  true,
}

func isAllowedRequestHeader(key string) bool {
	return allowedRequestHeaders[strings.ToLower(key)]
}

var allowedSubresources = map[string]bool{
	"log":  true,
	"logs": true,
}

type Client struct {
	log         *logging.Logger
	proxyClient proxypb.ClusterProxyClient
	httpClient  *http.Client
	kubeHost    *url.URL
}

func NewClient(log *logging.Logger, proxyClient proxypb.ClusterProxyClient, httpClient *http.Client, kubeHost string) (*Client, error) {
	parsed, err := url.Parse(kubeHost)
	if err != nil {
		return nil, fmt.Errorf("parsing kube host URL: %w", err)
	}
	return &Client{
		log:         log,
		proxyClient: proxyClient,
		httpClient:  httpClient,
		kubeHost:    parsed,
	}, nil
}

func (c *Client) Run(ctx context.Context) error {
	c.log.Info("starting cluster proxy client")
	defer c.log.Info("stopping cluster proxy client")

	eb := backoff.NewExponentialBackOff()
	eb.InitialInterval = 1 * time.Second
	eb.MaxInterval = 30 * time.Second

	op := func() (struct{}, error) {
		err := c.subscribe(ctx)
		if ctx.Err() != nil {
			return struct{}{}, backoff.Permanent(ctx.Err())
		}
		c.log.Warnf("proxy subscription closed, reconnecting in %s: %v", eb.NextBackOff(), err)
		return struct{}{}, err
	}

	_, err := backoff.Retry(ctx, op,
		backoff.WithBackOff(eb),
	)
	return err
}

func (c *Client) subscribe(ctx context.Context) error {
	subCtx, subCancel := context.WithCancel(ctx)
	defer subCancel()

	stream, err := c.proxyClient.Subscribe(subCtx, &proxypb.SubscribeRequest{})
	if err != nil {
		return fmt.Errorf("subscribe: %w", err)
	}

	c.log.Info("subscribed to proxy requests")

	sem := make(chan struct{}, maxConcurrentRequests)
	var wg sync.WaitGroup

	for {
		req, err := stream.Recv()
		if err != nil {
			subCancel()
			wg.Wait()
			return fmt.Errorf("recv: %w", err)
		}

		if len(sem) == maxConcurrentRequests {
			c.log.Warnf("max concurrent requests (%d) reached, waiting for slot", maxConcurrentRequests)
		}
		select {
		case sem <- struct{}{}:
		case <-subCtx.Done():
			wg.Wait()
			return subCtx.Err()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			c.handleRequest(subCtx, req)
		}()
	}
}

func (c *Client) handleRequest(ctx context.Context, req *proxypb.HttpRequest) {
	log := c.log.With("request_id", req.RequestId, "method", req.Method, "path", req.Path)

	if err := validateRequest(req); err != nil {
		log.Warnf("invalid request: %v", err)
		c.sendErrorResponse(ctx, req.RequestId, http.StatusBadRequest, err.Error())
		return
	}

	sanitized := sanitizeRequestURL(req.Path)
	pathPart, rawQuery, _ := strings.Cut(sanitized, "?")
	reqURL := *c.kubeHost
	reqURL.Path = pathPart
	reqURL.RawQuery = rawQuery
	url := reqURL.String()
	var body io.Reader
	if len(req.Body) > 0 {
		body = bytes.NewReader(req.Body)
	}
	httpReq, err := http.NewRequestWithContext(ctx, req.Method, url, body)
	if err != nil {
		log.Warnf("creating http request: %v", err)
		c.sendErrorResponse(ctx, req.RequestId, http.StatusInternalServerError, "failed to create request")
		return
	}

	for _, h := range req.Headers {
		if !isAllowedRequestHeader(h.Key) {
			log.Debugf("stripped non-allowed request header: %s", h.Key)
			continue
		}
		for _, v := range h.Values {
			httpReq.Header.Add(h.Key, v)
		}
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		log.Warnf("executing k8s request: %v", err)
		c.sendErrorResponse(ctx, req.RequestId, http.StatusBadGateway, "failed to reach kubernetes api")
		return
	}
	defer resp.Body.Close()

	log.Debugf("k8s response status: %d", resp.StatusCode)

	if err := c.streamResponse(ctx, log, req.RequestId, resp); err != nil {
		log.Warnf("streaming response: %v", err)
	}
}

func (c *Client) streamResponse(ctx context.Context, log *logging.Logger, requestID string, resp *http.Response) error {
	sendCtx, sendCancel := context.WithTimeout(ctx, sendResponseTimeout)
	defer sendCancel()

	sendStream, err := c.proxyClient.SendResponse(sendCtx)
	if err != nil {
		return fmt.Errorf("opening send stream: %w", err)
	}

	headers := filterResponseHeaders(resp.Header)

	buf := make([]byte, maxResponseChunkSize)
	first := true
	chunks, totalBytes := 0, 0
	for {
		n, readErr := resp.Body.Read(buf)
		isLast := readErr != nil

		if n > 0 {
			msg := &proxypb.HttpResponse{
				RequestId: requestID,
				Body:      buf[:n],
				More:      !isLast,
			}
			if first {
				msg.StatusCode = int32(resp.StatusCode) //nolint:gosec // G115: HTTP status codes are 1xx-5xx, no overflow risk
				msg.Headers = headers
				first = false
			}
			if err := sendStream.Send(msg); err != nil {
				return fmt.Errorf("send response chunk: %w", err)
			}
			chunks++
			totalBytes += n
		}

		// EOF with 0 bytes means the previous chunk was already sent with More=true
		// (we didn't know it was last until this read). Send an explicit terminator.
		if readErr == io.EOF {
			if n == 0 && !first {
				if err := sendStream.Send(&proxypb.HttpResponse{
					RequestId: requestID,
					More:      false,
				}); err != nil {
					return fmt.Errorf("send response chunk: %w", err)
				}
			}
			break
		}
		if readErr != nil {
			_ = sendStream.Send(&proxypb.HttpResponse{
				RequestId: requestID,
				Error:     readErr.Error(),
			})
			break
		}
	}

	if first {
		if err := sendStream.Send(&proxypb.HttpResponse{
			RequestId:  requestID,
			StatusCode: int32(resp.StatusCode), //nolint:gosec // G115: HTTP status codes are 1xx-5xx, no overflow risk
			Headers:    headers,
		}); err != nil {
			return fmt.Errorf("send empty response: %w", err)
		}
	}

	if _, err := sendStream.CloseAndRecv(); err != nil {
		return fmt.Errorf("close send stream: %w", err)
	}
	log.Debugf("response streamed: chunks=%d bytes=%d", chunks, totalBytes)
	return nil
}


func (c *Client) sendErrorResponse(ctx context.Context, requestID string, statusCode int, errMsg string) {
	sendCtx, sendCancel := context.WithTimeout(ctx, sendResponseTimeout)
	defer sendCancel()

	sendStream, err := c.proxyClient.SendResponse(sendCtx)
	if err != nil {
		c.log.Warnf("opening error send stream: %v", err)
		return
	}

	_ = sendStream.Send(&proxypb.HttpResponse{
		RequestId:  requestID,
		StatusCode: int32(statusCode), //nolint:gosec // G115: HTTP status codes are 1xx-5xx, no overflow risk
		Error:      errMsg,
	})
	_, _ = sendStream.CloseAndRecv()
}

func validateRequest(req *proxypb.HttpRequest) error {
	if req.Method != http.MethodGet {
		return fmt.Errorf("only GET requests are allowed, got %s", req.Method)
	}

	pathPart, query, _ := strings.Cut(req.Path, "?")
	if strings.ContainsRune(pathPart, '%') {
		return fmt.Errorf("percent-encoded characters are not allowed in path: %q", req.Path)
	}
	if strings.ContainsRune(query, '%') {
		return fmt.Errorf("percent-encoded characters are not allowed in query: %q", req.Path)
	}
	cleaned := path.Clean(pathPart)
	if !isAllowedPath(cleaned) {
		return fmt.Errorf("path %q is not allowed, must start with /api/ or /apis/", req.Path)
	}

	subresource := extractSubresource(cleaned)
	if subresource != "" && !allowedSubresources[subresource] {
		return fmt.Errorf("subresource %q is not allowed", subresource)
	}

	return nil
}

func sanitizeRequestURL(raw string) string {
	pathPart, query, _ := strings.Cut(raw, "?")
	cleaned := path.Clean(pathPart)
	if query != "" {
		return cleaned + "?" + query
	}
	return cleaned
}

func isAllowedPath(p string) bool {
	return p == "/api" || p == "/apis" ||
		strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/apis/")
}

func extractSubresource(path string) string {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")

	// /api/v1/... → 2, /apis/{group}/{version}/... → 3
	prefixLen := 2
	if len(parts) > 0 && parts[0] == "apis" {
		prefixLen = 3
	}
	if len(parts) <= prefixLen {
		return ""
	}

	rest := parts[prefixLen:]

	// /api/v1/namespaces/{ns}/pods/mypod/exec → [pods, mypod, exec]
	if len(rest) >= 2 && rest[0] == "namespaces" {
		rest = rest[2:]
	}

	// /api/v1/pods/mypod → no subresource; /api/v1/pods/mypod/exec → "exec"
	// /api/v1/nodes/my-node/proxy/some/path → "proxy" (not "path")
	if len(rest) < 3 {
		return ""
	}
	return rest[2]
}

func filterResponseHeaders(headers http.Header) []*proxypb.Header {
	var result []*proxypb.Header
	for k, v := range headers {
		if allowedResponseHeaders[k] {
			result = append(result, &proxypb.Header{
				Key:    k,
				Values: v,
			})
		}
	}
	return result
}
