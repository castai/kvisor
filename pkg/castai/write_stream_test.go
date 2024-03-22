package castai

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"go.uber.org/atomic"
	"go.uber.org/goleak"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestWriteStream(t *testing.T) {
	defer goleak.VerifyNone(t)

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

	serverStreamOpenCount := atomic.NewInt64(0)
	srv := &testServer{
		eventsWriteStreamHandler: func(server castaipb.RuntimeSecurityAgentAPI_EventsWriteStreamServer) error {
			serverStreamOpenCount.Add(1)
			var count int
			for {
				_, _ = server.Recv()
				count++
				if count > 10 {
					return status.Error(codes.Internal, "internal error")
				}
			}
		},
	}
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

	ws := NewWriteStream[*castaipb.Event, *castaipb.WriteStreamResponse](ctx, func(ctx context.Context) (grpc.ClientStream, error) {
		return client.GRPC.EventsWriteStream(ctx)
	})
	ws.ReopenDelay = 1 * time.Millisecond

	var errs []error
	for i := 0; i < 100; i++ {
		if err := ws.Send(&castaipb.Event{}); err != nil {
			errs = append(errs, err)
		}
		time.Sleep(1 * time.Millisecond)
	}

	timeout := time.After(2 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	for {
		select {
		case <-timeout:
			t.Fatal("timeout")
		case <-ticker.C:
			if serverStreamOpenCount.Load() > 0 && len(errs) > 0 {
				return
			}
		}
	}
}
