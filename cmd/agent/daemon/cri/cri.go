package cri

import (
	"context"
	"fmt"
	"net/url"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	criapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

func NewRuntimeClient(ctx context.Context, endpoint string) (criapi.RuntimeServiceClient, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "unix" {
		return nil, fmt.Errorf("only unix socket is supported")
	}

	conn, err := grpc.NewClient(endpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to CRI runtime: %w", err)
	}
	rtcli := criapi.NewRuntimeServiceClient(conn)
	if _, err := rtcli.Version(ctx, &criapi.VersionRequest{}); err != nil {
		return nil, fmt.Errorf("failed CRI version check: %w", err)
	}

	return rtcli, nil
}
