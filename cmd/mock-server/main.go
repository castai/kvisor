package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os/signal"
	"syscall"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/logging"
	"google.golang.org/grpc"
	_ "google.golang.org/grpc/encoding/gzip"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	log := logging.New(&logging.Config{
		Level: slog.LevelDebug,
	})

	// nolint:gosec
	lis, err := net.Listen("tcp", ":8443")
	if err != nil {
		log.Fatal(err.Error())
	}
	defer lis.Close()

	srv := grpc.NewServer()
	castaipb.RegisterRuntimeSecurityAgentAPIServer(srv, NewMockServer(log))

	go func() {
		<-ctx.Done()
		log.Info("shutting down grpc ingestor server")
		srv.Stop()
	}()

	fmt.Println("listening at :8443")
	if err := srv.Serve(lis); err != nil {
		log.Fatal(err.Error())
	}
}

var _ castaipb.RuntimeSecurityAgentAPIServer = (*MockServer)(nil)

func NewMockServer(log *logging.Logger) *MockServer {
	return &MockServer{
		log: log.WithField("component", "mock_castai"),
	}
}

type MockServer struct {
	log *logging.Logger
}

func (m *MockServer) ProcessEventsWriteStream(g grpc.ClientStreamingServer[castaipb.ProcessTreeEvent, castaipb.WriteStreamResponse]) error {
	return nil
}

func (m *MockServer) WriteDataBatch(ctx context.Context, req *castaipb.WriteDataBatchRequest) (*castaipb.WriteDataBatchResponse, error) {
	for _, item := range req.Items {
		m.log.Debugf("data batch item: %v", item)
	}
	return &castaipb.WriteDataBatchResponse{}, nil
}

func (m *MockServer) KubeBenchReportIngest(ctx context.Context, in *castaipb.KubeBenchReport) (*castaipb.KubeBenchReportIngestResponse, error) {
	m.log.Debugf("KubeBenchReportIngest: %v", in)
	return &castaipb.KubeBenchReportIngestResponse{}, nil
}

func (m *MockServer) KubeLinterReportIngest(ctx context.Context, in *castaipb.KubeLinterReport) (*castaipb.KubeLinterReportIngestResponse, error) {
	m.log.Debugf("KubeLinterReportIngest: %v", in)
	return &castaipb.KubeLinterReportIngestResponse{}, nil
}

func (m *MockServer) GetSyncState(ctx context.Context, in *castaipb.GetSyncStateRequest) (*castaipb.GetSyncStateResponse, error) {
	m.log.Debugf("GetSyncState: %v", in.ImageIds)
	return &castaipb.GetSyncStateResponse{}, nil
}

func (m *MockServer) ImageMetadataIngest(ctx context.Context, in *castaipb.ImageMetadata) (*castaipb.ImageMetadataIngestResponse, error) {
	m.log.Debugf("ImageMetadataIngest: %v", in)
	return &castaipb.ImageMetadataIngestResponse{}, nil
}

func (m *MockServer) UpdateSyncState(ctx context.Context, in *castaipb.UpdateSyncStateRequest) (*castaipb.UpdateSyncStateResponse, error) {
	m.log.Debugf("UpdateSyncState: %v", in)
	return &castaipb.UpdateSyncStateResponse{}, nil
}

func (m *MockServer) GetConfiguration(ctx context.Context, in *castaipb.GetConfigurationRequest) (*castaipb.GetConfigurationResponse, error) {
	m.log.Debugf("GetConfiguration: %v", in)
	return &castaipb.GetConfigurationResponse{}, nil
}

func (m *MockServer) LogsWriteStream(server castaipb.RuntimeSecurityAgentAPI_LogsWriteStreamServer) error {
	for {
		event, err := server.Recv()
		if err != nil {
			return err
		}
		m.log.Debugf("log: %v", event)
	}
}
