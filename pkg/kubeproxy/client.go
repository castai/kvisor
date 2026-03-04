package kubeproxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v5"
	"google.golang.org/grpc/codes"

	proxypb "github.com/castai/kvisor/api/v1/proxy"
	"github.com/castai/kvisor/pkg/castai"
	"github.com/castai/logging"
)

const (
	maxConcurrentRequests = 50
	maxResponseChunkSize  = 32 * 1024
	sendResponseTimeout   = 30 * time.Second
)

var allowedResponseHeaders = map[string]bool{
	"Content-Type":                      true,
	"Content-Length":                    true,
	"Content-Encoding":                  true,
	"Cache-Control":                     true,
	"Date":                              true,
	"X-Kubernetes-Pf-Flowschema-Uid":    true,
	"X-Kubernetes-Pf-Prioritylevel-Uid": true,
}

var blockedRequestHeaders = map[string]bool{
	"authorization":       true,
	"impersonate-user":    true,
	"impersonate-group":   true,
	"impersonate-uid":     true,
}

func isBlockedRequestHeader(key string) bool {
	lower := strings.ToLower(key)
	return blockedRequestHeaders[lower] || strings.HasPrefix(lower, "impersonate-extra-")
}

var blockedSubresources = map[string]bool{
	"exec":        true,
	"attach":      true,
	"portforward": true,
	"proxy":       true,
}

type Client struct {
	log         *logging.Logger
	proxyClient proxypb.KubernetesProxyClient
	httpClient  *http.Client
	kubeHost    string
}

func NewClient(log *logging.Logger, proxyClient proxypb.KubernetesProxyClient, httpClient *http.Client, kubeHost string) *Client {
	return &Client{
		log:         log,
		proxyClient: proxyClient,
		httpClient:  httpClient,
		kubeHost:    kubeHost,
	}
}

func (c *Client) Run(ctx context.Context) error {
	c.log.Info("starting kube proxy client")
	defer c.log.Info("stopping kube proxy client")

	op := func() (struct{}, error) {
		err := c.subscribe(ctx)
		if ctx.Err() != nil {
			return struct{}{}, backoff.Permanent(ctx.Err())
		}
		if castai.IsGRPCError(err, codes.PermissionDenied, codes.Unauthenticated, codes.Unimplemented) {
			c.log.Errorf("proxy subscription failed permanently: %v", err)
			return struct{}{}, backoff.Permanent(err)
		}
		c.log.Warnf("proxy subscription closed, reconnecting: %v", err)
		return struct{}{}, err
	}

	eb := backoff.NewExponentialBackOff()
	eb.InitialInterval = 1 * time.Second
	eb.MaxInterval = 30 * time.Second

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

	url := fmt.Sprintf("%s%s", c.kubeHost, sanitizeRequestURL(req.Path))
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
		if isBlockedRequestHeader(h.Key) {
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

	if err := c.streamResponse(ctx, req.RequestId, resp); err != nil {
		log.Warnf("streaming response: %v", err)
	}
}

func (c *Client) streamResponse(ctx context.Context, requestID string, resp *http.Response) error {
	sendCtx, sendCancel := context.WithTimeout(ctx, sendResponseTimeout)
	defer sendCancel()

	sendStream, err := c.proxyClient.SendResponse(sendCtx)
	if err != nil {
		return fmt.Errorf("opening send stream: %w", err)
	}

	headers := filterResponseHeaders(resp.Header)

	buf := make([]byte, maxResponseChunkSize)
	first := true
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
				msg.StatusCode = int32(resp.StatusCode)
				msg.Headers = headers
				first = false
			}
			if err := sendStream.Send(msg); err != nil {
				return fmt.Errorf("send response chunk: %w", err)
			}
		}

		if readErr == io.EOF {
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
			StatusCode: int32(resp.StatusCode),
			Headers:    headers,
		}); err != nil {
			return fmt.Errorf("send empty response: %w", err)
		}
	}

	if _, err := sendStream.CloseAndRecv(); err != nil {
		return fmt.Errorf("close send stream: %w", err)
	}
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
		StatusCode: int32(statusCode),
		Error:      errMsg,
	})
	_, _ = sendStream.CloseAndRecv()
}

func validateRequest(req *proxypb.HttpRequest) error {
	if req.Method != http.MethodGet {
		return fmt.Errorf("only GET requests are allowed, got %s", req.Method)
	}

	pathPart, _, _ := strings.Cut(req.Path, "?")
	cleaned := cleanPath(pathPart)
	if !isAllowedPath(cleaned) {
		return fmt.Errorf("path %q is not allowed, must start with /api/ or /apis/", req.Path)
	}

	subresource := extractSubresource(cleaned)
	if blockedSubresources[subresource] {
		return fmt.Errorf("subresource %q is not allowed", subresource)
	}

	return nil
}

func cleanPath(p string) string {
	return path.Clean(p)
}

func sanitizeRequestURL(raw string) string {
	pathPart, query, _ := strings.Cut(raw, "?")
	cleaned := cleanPath(pathPart)
	if query != "" {
		return cleaned + "?" + query
	}
	return cleaned
}

func isAllowedPath(p string) bool {
	return strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/apis/")
}

func extractSubresource(path string) string {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")

	// /api/v1/namespaces/{ns}/pods/{name}/{subresource}
	// /apis/{group}/{version}/namespaces/{ns}/{resource}/{name}/{subresource}
	if len(parts) < 2 {
		return ""
	}

	hasNamespaces := false
	for i, p := range parts {
		if p == "namespaces" && i+1 < len(parts) {
			hasNamespaces = true
			rest := parts[i+2:]
			if len(rest) >= 3 {
				return rest[2]
			}
			return ""
		}
	}

	if !hasNamespaces {
		// /api/v1/{resource}/{name}/{subresource}
		// /apis/{group}/{version}/{resource}/{name}/{subresource}
		startIdx := 2
		if parts[0] == "apis" {
			startIdx = 3
		}
		if len(parts) > startIdx+2 {
			return parts[startIdx+2]
		}
	}

	return ""
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
