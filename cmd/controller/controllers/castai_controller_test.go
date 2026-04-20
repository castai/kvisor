package controllers

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"k8s.io/client-go/kubernetes/fake"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/controller/kube"
	"github.com/castai/kvisor/pkg/castai"
	"github.com/castai/logging"
)

func TestCastaiController(t *testing.T) {
	log := logging.New()
	k8sClient := fake.NewSimpleClientset()
	kubeClient := kube.NewClient(log, "agent", "ns", kube.Version{}, k8sClient, "", false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Run("stop on initial config failure after max elapsed time", func(t *testing.T) {
		r := require.New(t)
		client := &testGrpcClient{
			getConfigurationResponse: func() (*castaipb.GetConfigurationResponse, error) {
				return nil, errors.New("ups")
			},
		}
		ctrl := newTestCastaiController(log, kubeClient, client)
		ctrl.remoteConfigBackoff.MaxElapsedTime = 50 * time.Millisecond
		err := ctrl.Run(ctx)
		r.EqualError(err, "fetching initial config: ups")
	})

	t.Run("stop on initial config failure when context is cancelled", func(t *testing.T) {
		r := require.New(t)
		cancelCtx, cancelFn := context.WithCancel(ctx)
		calls := 0
		client := &testGrpcClient{
			getConfigurationResponse: func() (*castaipb.GetConfigurationResponse, error) {
				calls++
				if calls >= 3 {
					cancelFn()
				}
				return nil, errors.New("ups")
			},
		}
		ctrl := newTestCastaiController(log, kubeClient, client)
		err := ctrl.Run(cancelCtx)
		r.ErrorIs(err, context.Canceled)
	})

	t.Run("retries initial config fetch until success", func(t *testing.T) {
		r := require.New(t)
		calls := 0
		client := &testGrpcClient{
			getConfigurationResponse: func() (*castaipb.GetConfigurationResponse, error) {
				calls++
				if calls < 3 {
					return nil, errors.New("ups")
				}
				return &castaipb.GetConfigurationResponse{}, nil
			},
		}
		ctrl := newTestCastaiController(log, kubeClient, client)
		r.NoError(ctrl.fetchInitialRemoteConfig(ctx))
		r.Equal(3, calls)
	})

	t.Run("stop on config loop failure after max retries", func(t *testing.T) {
		r := require.New(t)
		calls := 0
		client := &testGrpcClient{
			getConfigurationResponse: func() (*castaipb.GetConfigurationResponse, error) {
				calls++
				// Do not fail to first call to pass initial config sync.
				if calls == 1 {
					return &castaipb.GetConfigurationResponse{}, nil
				}
				return nil, errors.New("ups")
			},
		}
		ctrl := newTestCastaiController(log, kubeClient, client)
		ctrl.removeConfigMaxFailures = 3
		err := ctrl.Run(ctx)
		r.ErrorContains(err, "remote config fetch errors reached")
	})
}

func newTestCastaiController(log *logging.Logger, kubeClient *kube.Client, client *testGrpcClient) *CastaiController {
	castaiClient := &castai.Client{
		GRPC: client,
	}
	cfg := CastaiConfig{
		RemoteConfigSyncDuration: 10 * time.Millisecond,
	}
	ctrl := NewCastaiController(log, cfg, []byte{}, kubeClient, castaiClient)
	ctrl.remoteConfigBackoff = backoffConfig{
		InitInterval:   10 * time.Millisecond,
		MaxInterval:    50 * time.Millisecond,
		MaxElapsedTime: 5 * time.Minute,
	}
	return ctrl
}

type testGrpcClient struct {
	getConfigurationResponse func() (*castaipb.GetConfigurationResponse, error)
}

func (t testGrpcClient) LogsWriteStream(ctx context.Context, opts ...grpc.CallOption) (grpc.ClientStreamingClient[castaipb.LogEvent, castaipb.WriteStreamResponse], error) {
	return nil, nil
}

func (t testGrpcClient) WriteDataBatch(ctx context.Context, in *castaipb.WriteDataBatchRequest, opts ...grpc.CallOption) (*castaipb.WriteDataBatchResponse, error) {
	return nil, nil
}

var _ castaipb.RuntimeSecurityAgentAPIClient = testGrpcClient{}

func (t testGrpcClient) KubeBenchReportIngest(ctx context.Context, in *castaipb.KubeBenchReport, opts ...grpc.CallOption) (*castaipb.KubeBenchReportIngestResponse, error) {
	return nil, nil
}

func (t testGrpcClient) KubeLinterReportIngest(ctx context.Context, in *castaipb.KubeLinterReport, opts ...grpc.CallOption) (*castaipb.KubeLinterReportIngestResponse, error) {
	return nil, nil
}

func (t testGrpcClient) ImageMetadataIngest(ctx context.Context, in *castaipb.ImageMetadata, opts ...grpc.CallOption) (*castaipb.ImageMetadataIngestResponse, error) {
	return nil, nil
}

func (t testGrpcClient) GetSyncState(ctx context.Context, in *castaipb.GetSyncStateRequest, opts ...grpc.CallOption) (*castaipb.GetSyncStateResponse, error) {
	return nil, nil
}

func (t testGrpcClient) UpdateSyncState(ctx context.Context, in *castaipb.UpdateSyncStateRequest, opts ...grpc.CallOption) (*castaipb.UpdateSyncStateResponse, error) {
	return nil, nil
}

func (t testGrpcClient) GetConfiguration(ctx context.Context, in *castaipb.GetConfigurationRequest, opts ...grpc.CallOption) (*castaipb.GetConfigurationResponse, error) {
	if t.getConfigurationResponse != nil {
		return t.getConfigurationResponse()
	}
	return &castaipb.GetConfigurationResponse{}, nil
}
