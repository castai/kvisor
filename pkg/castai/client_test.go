package castai

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func TestClient(t *testing.T) {
	r := require.New(t)
	ctx := context.Background()

	// Setup grpc test server which implements castai api.
	ports, err := allocatePorts(1)
	r.NoError(err)
	addr := fmt.Sprintf("localhost:%d", ports[0])
	lis, err := net.Listen("tcp", addr)
	r.NoError(err)
	defer lis.Close()
	s := grpc.NewServer()
	srv := &testServer{}
	castaipb.RegisterRuntimeSecurityAgentAPIServer(s, srv)
	go s.Serve(lis)

	clusterID := uuid.NewString()
	client, err := NewClient("test", Config{
		ClusterID:   clusterID,
		APIKey:      "api-key",
		APIGrpcAddr: addr,
	})
	r.NoError(err)
	defer client.Close()

	ctx = metadata.AppendToOutgoingContext(ctx, "x-custom", "1")
	_, err = client.GRPC.GetConfiguration(ctx, &castaipb.GetConfigurationRequest{})
	r.NoError(err)

	eventsStream, err := client.GRPC.EventsWriteStream(ctx)
	r.NoError(err)
	r.NoError(eventsStream.Send(&castaipb.Event{}))
	r.NoError(eventsStream.Send(&castaipb.Event{}))
	r.NoError(eventsStream.CloseSend())
}

func TestRemote(t *testing.T) {
	apiKey := os.Getenv("API_KEY")
	if apiKey == "" {
		t.Skip()
	}
	addr := os.Getenv("API_ADDR")
	if addr == "" {
		addr = "kvisor.prod-master.cast.ai:443"
	}
	r := require.New(t)
	ctx := context.Background()
	client, err := NewClient("kvisord-test", Config{
		ClusterID:   uuid.NewString(),
		APIKey:      apiKey,
		APIGrpcAddr: addr,
	})
	r.NoError(err)
	defer client.Close()

	var errg errgroup.Group
	errg.Go(func() error {
		_, err = client.GRPC.GetConfiguration(ctx, &castaipb.GetConfigurationRequest{})
		r.NoError(err)

		var logsStream castaipb.RuntimeSecurityAgentAPI_LogsWriteStreamClient
		for {
			if logsStream == nil {
				logsStream, err = client.GRPC.LogsWriteStream(ctx)
				if err != nil {
					fmt.Printf("create stream err: %v\n", err)
					time.Sleep(1 * time.Second)
					continue
				}
			}
			err = logsStream.Send(&castaipb.LogEvent{
				Level: 0,
				Msg:   "test msg",
			})
			if err != nil {
				logsStream = nil
				fmt.Printf("send stream err: %v\n", err)
				continue
			}
			time.Sleep(3 * time.Second)
			fmt.Println("sent logs", time.Now().Unix())
		}

	})

	r.NoError(errg.Wait())
}

type testServer struct {
	eventsWriteStreamHandler func(server castaipb.RuntimeSecurityAgentAPI_EventsWriteStreamServer) error
}

func (t *testServer) KubeBenchReportIngest(ctx context.Context, report *castaipb.KubeBenchReport) (*castaipb.KubeBenchReportIngestResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (t *testServer) KubeLinterReportIngest(ctx context.Context, report *castaipb.KubeLinterReport) (*castaipb.KubeLinterReportIngestResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (t *testServer) ImageMetadataIngest(ctx context.Context, imageMetadata *castaipb.ImageMetadata) (*castaipb.ImageMetadataIngestResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (t *testServer) GetSyncState(ctx context.Context, request *castaipb.GetSyncStateRequest) (*castaipb.GetSyncStateResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (t *testServer) UpdateSyncState(ctx context.Context, request *castaipb.UpdateSyncStateRequest) (*castaipb.UpdateSyncStateResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (*testServer) KubernetesDeltaIngest(castaipb.RuntimeSecurityAgentAPI_KubernetesDeltaIngestServer) error {
	//TODO implement me
	panic("unimplemented")
}

func (t *testServer) ContainerStatsWriteStream(server castaipb.RuntimeSecurityAgentAPI_ContainerStatsWriteStreamServer) error {
	//TODO implement me
	panic("implement me")
}

func (t *testServer) GetConfiguration(ctx context.Context, request *castaipb.GetConfigurationRequest) (*castaipb.GetConfigurationResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errors.New("no metadata")
	}
	fmt.Println(md)
	token := md["authorization"]
	if len(token) == 0 {
		return nil, errors.New("no authorization")
	}
	if token[0] != "Token api-key" {
		return nil, fmt.Errorf("invalid token %s", token[0])
	}
	return &castaipb.GetConfigurationResponse{}, nil
}

func (t *testServer) EventsWriteStream(server castaipb.RuntimeSecurityAgentAPI_EventsWriteStreamServer) error {
	if t.eventsWriteStreamHandler != nil {
		return t.eventsWriteStreamHandler(server)
	}
	
	md, ok := metadata.FromIncomingContext(server.Context())
	if !ok {
		return errors.New("no metadata")
	}
	token := md["authorization"]
	if len(token) == 0 {
		return errors.New("no authorization")
	}
	if token[0] != "Token api-key" {
		return fmt.Errorf("invalid token %s", token[0])
	}
	for {
		event, err := server.Recv()
		if err != nil {
			return err
		}
		fmt.Println("event", event)
	}
}

func (t *testServer) LogsWriteStream(server castaipb.RuntimeSecurityAgentAPI_LogsWriteStreamServer) error {
	//TODO implement me
	panic("implement me")
}

func allocatePorts(n int) ([]int, error) {
	var listeners []net.Listener
	for i := 0; i < n; i++ {
		addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
		if err != nil {
			return nil, err
		}

		l, err := net.ListenTCP("tcp", addr)
		if err != nil {
			return nil, err
		}
		listeners = append(listeners, l)
	}

	ports := make([]int, 0, n)
	for _, l := range listeners {
		ports = append(ports, l.Addr().(*net.TCPAddr).Port)
		l.Close()
	}

	return ports, nil
}
