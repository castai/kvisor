package state

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/controller/kube"
	"github.com/castai/kvisor/pkg/castai"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"k8s.io/client-go/kubernetes/fake"
)

func TestCastaiController(t *testing.T) {
	log := logging.New(&logging.Config{
		Level: slog.LevelDebug,
	})
	k8sClient := fake.NewSimpleClientset()
	kubeClient := kube.NewClient(log, "agent", "ns", kube.Version{}, k8sClient)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Run("stop on initial config failure", func(t *testing.T) {
		r := require.New(t)
		client := &testGrpcClient{
			getConfigurationResponse: func() (*castaipb.GetConfigurationResponse, error) {
				return nil, errors.New("ups")
			},
		}
		ctrl := newTestCastaiController(log, kubeClient, client)
		ctrl.remoteConfigInitialSyncTimeout = 50 * time.Millisecond
		ctrl.remoteConfigRetryWaitDuration = 10 * time.Millisecond
		err := ctrl.Run(ctx)
		r.ErrorIs(err, context.DeadlineExceeded)
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
		ctrl.remoteConfigInitialSyncTimeout = 50 * time.Millisecond
		ctrl.remoteConfigRetryWaitDuration = 10 * time.Millisecond
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
	return NewCastaiController(log, cfg, []byte{}, kubeClient, castaiClient)
}

type testGrpcClient struct {
	getConfigurationResponse func() (*castaipb.GetConfigurationResponse, error)
}

var _ castaipb.RuntimeSecurityAgentAPIClient = testGrpcClient{}

func (t testGrpcClient) ProcessEventsWriteStream(ctx context.Context, opts ...grpc.CallOption) (castaipb.RuntimeSecurityAgentAPI_ProcessEventsWriteStreamClient, error) {
	return nil, nil
}

func (t testGrpcClient) KubernetesDeltaBatchIngest(ctx context.Context, opts ...grpc.CallOption) (castaipb.RuntimeSecurityAgentAPI_KubernetesDeltaBatchIngestClient, error) {
	return nil, nil
}

func (t testGrpcClient) NetflowWriteStream(ctx context.Context, opts ...grpc.CallOption) (castaipb.RuntimeSecurityAgentAPI_NetflowWriteStreamClient, error) {
	return nil, nil
}

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

func (t testGrpcClient) EventsWriteStream(ctx context.Context, opts ...grpc.CallOption) (castaipb.RuntimeSecurityAgentAPI_EventsWriteStreamClient, error) {
	return nil, nil
}

func (t testGrpcClient) LogsWriteStream(ctx context.Context, opts ...grpc.CallOption) (castaipb.RuntimeSecurityAgentAPI_LogsWriteStreamClient, error) {
	return nil, nil
}

func (t testGrpcClient) StatsWriteStream(ctx context.Context, opts ...grpc.CallOption) (castaipb.RuntimeSecurityAgentAPI_StatsWriteStreamClient, error) {
	return nil, nil
}

func (testGrpcClient) KubernetesDeltaIngest(ctx context.Context, opts ...grpc.CallOption) (castaipb.RuntimeSecurityAgentAPI_KubernetesDeltaIngestClient, error) {
	return nil, nil
}
