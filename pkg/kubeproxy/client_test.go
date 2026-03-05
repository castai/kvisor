package kubeproxy

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	proxypb "github.com/castai/kvisor/api/v1/proxy"
)

func TestValidateRequest(t *testing.T) {
	tests := []struct {
		name    string
		req     *proxypb.HttpRequest
		wantErr string
	}{
		{
			name: "valid GET to core API",
			req: &proxypb.HttpRequest{
				Method: http.MethodGet,
				Path:   "/api/v1/namespaces/default/pods",
			},
		},
		{
			name: "valid GET to extended API",
			req: &proxypb.HttpRequest{
				Method: http.MethodGet,
				Path:   "/apis/apps/v1/namespaces/kube-system/deployments/coredns",
			},
		},
		{
			name: "valid GET to list all pods",
			req: &proxypb.HttpRequest{
				Method: http.MethodGet,
				Path:   "/api/v1/pods",
			},
		},
		{
			name: "POST rejected",
			req: &proxypb.HttpRequest{
				Method: http.MethodPost,
				Path:   "/api/v1/namespaces/default/pods",
			},
			wantErr: "only GET requests are allowed",
		},
		{
			name: "DELETE rejected",
			req: &proxypb.HttpRequest{
				Method: http.MethodDelete,
				Path:   "/api/v1/namespaces/default/pods/my-pod",
			},
			wantErr: "only GET requests are allowed",
		},
		{
			name: "/healthz path rejected",
			req: &proxypb.HttpRequest{
				Method: http.MethodGet,
				Path:   "/healthz",
			},
			wantErr: "path \"/healthz\" is not allowed",
		},
		{
			name: "/metrics path rejected",
			req: &proxypb.HttpRequest{
				Method: http.MethodGet,
				Path:   "/metrics",
			},
			wantErr: "is not allowed",
		},
		{
			name: "/debug/pprof path rejected",
			req: &proxypb.HttpRequest{
				Method: http.MethodGet,
				Path:   "/debug/pprof/",
			},
			wantErr: "is not allowed",
		},
		{
			name: "root path rejected",
			req: &proxypb.HttpRequest{
				Method: http.MethodGet,
				Path:   "/",
			},
			wantErr: "is not allowed",
		},
		{
			name: "exec subresource blocked",
			req: &proxypb.HttpRequest{
				Method: http.MethodGet,
				Path:   "/api/v1/namespaces/default/pods/my-pod/exec",
			},
			wantErr: `subresource "exec" is not allowed`,
		},
		{
			name: "attach subresource blocked",
			req: &proxypb.HttpRequest{
				Method: http.MethodGet,
				Path:   "/api/v1/namespaces/default/pods/my-pod/attach",
			},
			wantErr: `subresource "attach" is not allowed`,
		},
		{
			name: "portforward subresource blocked",
			req: &proxypb.HttpRequest{
				Method: http.MethodGet,
				Path:   "/api/v1/namespaces/default/pods/my-pod/portforward",
			},
			wantErr: `subresource "portforward" is not allowed`,
		},
		{
			name: "log subresource allowed",
			req: &proxypb.HttpRequest{
				Method: http.MethodGet,
				Path:   "/api/v1/namespaces/default/pods/my-pod/log",
			},
		},
		{
			name: "logs subresource allowed",
			req: &proxypb.HttpRequest{
				Method: http.MethodGet,
				Path:   "/api/v1/namespaces/default/pods/my-pod/logs",
			},
		},
		{
			name: "proxy subresource blocked",
			req: &proxypb.HttpRequest{
				Method: http.MethodGet,
				Path:   "/api/v1/namespaces/default/pods/my-pod/proxy",
			},
			wantErr: `subresource "proxy" is not allowed`,
		},
		{
			name: "proxy subresource with trailing path blocked",
			req: &proxypb.HttpRequest{
				Method: http.MethodGet,
				Path:   "/api/v1/namespaces/default/services/my-svc/proxy/some/endpoint",
			},
			wantErr: `subresource "proxy" is not allowed`,
		},
		{
			name: "status subresource allowed",
			req: &proxypb.HttpRequest{
				Method: http.MethodGet,
				Path:   "/api/v1/namespaces/default/pods/my-pod/status",
			},
		},
		{
			name: "path traversal via .. rejected",
			req: &proxypb.HttpRequest{
				Method: http.MethodGet,
				Path:   "/api/v1/../../debug/pprof/",
			},
			wantErr: "is not allowed",
		},
		{
			name: "exec with query string still blocked",
			req: &proxypb.HttpRequest{
				Method: http.MethodGet,
				Path:   "/api/v1/namespaces/default/pods/my-pod/exec?command=ls",
			},
			wantErr: `subresource "exec" is not allowed`,
		},
		{
			name: "log with follow query string allowed",
			req: &proxypb.HttpRequest{
				Method: http.MethodGet,
				Path:   "/api/v1/namespaces/default/pods/my-pod/log?follow=true",
			},
		},
		{
			name: "valid path with query string allowed",
			req: &proxypb.HttpRequest{
				Method: http.MethodGet,
				Path:   "/api/v1/pods?labelSelector=app%3Dnginx",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRequest(tt.req)
			if tt.wantErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestExtractSubresource(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "no subresource - list pods",
			path: "/api/v1/pods",
			want: "",
		},
		{
			name: "no subresource - namespaced pods",
			path: "/api/v1/namespaces/default/pods",
			want: "",
		},
		{
			name: "no subresource - specific pod",
			path: "/api/v1/namespaces/default/pods/my-pod",
			want: "",
		},
		{
			name: "exec subresource",
			path: "/api/v1/namespaces/default/pods/my-pod/exec",
			want: "exec",
		},
		{
			name: "log subresource",
			path: "/api/v1/namespaces/default/pods/my-pod/log",
			want: "log",
		},
		{
			name: "status subresource on apps resource",
			path: "/apis/apps/v1/namespaces/default/deployments/my-deploy/status",
			want: "status",
		},
		{
			name: "cluster-scoped - nodes status",
			path: "/api/v1/nodes/my-node/status",
			want: "status",
		},
		{
			name: "cluster-scoped - no subresource",
			path: "/api/v1/nodes/my-node",
			want: "",
		},
		{
			name: "proxy subresource with trailing path - returns proxy not last segment",
			path: "/api/v1/nodes/my-node/proxy/some/path",
			want: "proxy",
		},
		{
			name: "proxy subresource with trailing path - namespaced service",
			path: "/api/v1/namespaces/default/services/my-svc/proxy/some/endpoint",
			want: "proxy",
		},
		{
			name: "empty path",
			path: "/",
			want: "",
		},
		{
			name: "just api version",
			path: "/api/v1",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractSubresource(tt.path)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestIsAllowedPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/api/v1/pods", true},
		{"/api/v1/namespaces/default/pods", true},
		{"/apis/apps/v1/deployments", true},
		{"/healthz", false},
		{"/metrics", false},
		{"/debug/pprof/", false},
		{"/", false},
		{"/version", false},
		{"/openapi/v2", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			require.Equal(t, tt.want, isAllowedPath(tt.path))
		})
	}
}

func TestFilterResponseHeaders(t *testing.T) {
	headers := http.Header{
		"Content-Type":    {"application/json"},
		"Content-Length":  {"1234"},
		"X-Secret-Header": {"should-be-filtered"},
		"Cache-Control":   {"no-cache"},
		"Set-Cookie":      {"should-be-filtered"},
	}

	result := filterResponseHeaders(headers)

	resultMap := make(map[string][]string)
	for _, h := range result {
		resultMap[h.Key] = h.Values
	}

	require.Contains(t, resultMap, "Content-Type")
	require.Contains(t, resultMap, "Content-Length")
	require.Contains(t, resultMap, "Cache-Control")
	require.NotContains(t, resultMap, "X-Secret-Header")
	require.NotContains(t, resultMap, "Set-Cookie")
}
