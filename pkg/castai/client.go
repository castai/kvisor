package castai

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/metadata"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
)

func NewGRPCConn(cfg Config, extraOpts ...grpc.DialOption) (*grpc.ClientConn, error) {
	tls := credentials.NewTLS(nil)
	if strings.HasPrefix(cfg.APIGrpcAddr, "localhost") || cfg.Insecure {
		tls = insecure.NewCredentials()
	}
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(tls),
		grpc.WithUnaryInterceptor(newCastaiGrpcUnaryMetadataInterceptor(cfg)),
		grpc.WithStreamInterceptor(newCastaiGrpcStreamMetadataInterceptor(cfg)),
	}
	opts = append(opts, extraOpts...)
	conn, err := grpc.NewClient(cfg.APIGrpcAddr, opts...)
	if err != nil {
		return nil, fmt.Errorf("castai grpc server dial: %w", err)
	}
	return conn, nil
}

func NewClient(userAgent string, cfg Config) (*Client, error) {
	grpcConn, err := NewGRPCConn(cfg, grpc.WithUserAgent(userAgent))
	if err != nil {
		return nil, err
	}
	if cfg.CompressionName == "" {
		cfg.CompressionName = gzip.Name
	}

	client := &Client{
		GRPC:            castaipb.NewRuntimeSecurityAgentAPIClient(grpcConn),
		grpcConn:        grpcConn,
		compressionName: cfg.CompressionName,
	}
	return client, nil
}

type Client struct {
	GRPC            castaipb.RuntimeSecurityAgentAPIClient
	grpcConn        *grpc.ClientConn
	compressionName string
}

func (c *Client) Close() {
	if c.grpcConn != nil {
		_ = c.grpcConn.Close()
	}
}

func (c *Client) GetCompressionName() string {
	return c.compressionName
}

func newCastaiGrpcUnaryMetadataInterceptor(cfg Config) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		ctx = withMetadataContext(ctx, cfg)
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

func newCastaiGrpcStreamMetadataInterceptor(cfg Config) grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		ctx = withMetadataContext(ctx, cfg)
		return streamer(ctx, desc, cc, method, opts...)
	}
}

func withMetadataContext(ctx context.Context, cfg Config) context.Context {
	return metadata.AppendToOutgoingContext(ctx,
		"x-cluster-id", cfg.ClusterID,
		"authorization", fmt.Sprintf("Token %s", cfg.APIKey),
	)
}
