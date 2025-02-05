package state

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func TestNewCastaiNetflowExporter(t *testing.T) {
	t.Run("send netflows", func(t *testing.T) {
		r := require.New(t)

		netflowStream := &netflowMockStream{}
		exporter := NewCastaiNetflowExporter(logging.NewTestLog(), netflowStream, 100)

		go func() {
			if err := exporter.Run(context.Background()); err != nil {
				panic(err)
			}
		}()
		for range 100 {
			exporter.Enqueue(&castaipb.Netflow{PodName: "p1"})
		}

		r.Eventually(func() bool {
			netflowStream.mu.Lock()
			streams := netflowStream.streams
			netflowStream.mu.Unlock()
			if len(streams) != 1 {
				return false
			}
			stream := streams[0]
			stream.mu.Lock()
			flows := stream.flows
			stream.mu.Unlock()
			if len(flows) != 100 {
				return false
			}
			r.Equal("p1", flows[0].PodName)
			return true
		}, 1*time.Second, 10*time.Millisecond)
	})

	t.Run("retry netflows", func(t *testing.T) {
		r := require.New(t)

		netflowStream := &netflowMockStream{firstSendError: true}
		exporter := NewCastaiNetflowExporter(logging.NewTestLog(), netflowStream, 100)
		exporter.writeStreamCreateRetryDelay = 1 * time.Millisecond

		go func() {
			if err := exporter.Run(context.Background()); err != nil {
				panic(err)
			}
		}()
		exporter.Enqueue(&castaipb.Netflow{PodName: "p1"})

		r.Eventually(func() bool {
			netflowStream.mu.Lock()
			streams := netflowStream.streams
			netflowStream.mu.Unlock()
			if len(streams) != 1 {
				return false
			}
			stream := streams[0]
			stream.mu.Lock()
			flows := stream.flows
			stream.mu.Unlock()
			if len(flows) != 1 {
				return false
			}
			r.Equal("p1", flows[0].PodName)
			return true
		}, 1*time.Second, 10*time.Millisecond)
	})
}

type netflowMockStream struct {
	mu             sync.Mutex
	streams        []*mockNetflowStreamClient
	firstSendError bool
}

func (n *netflowMockStream) NetflowWriteStream(ctx context.Context, opts ...grpc.CallOption) (castaipb.RuntimeSecurityAgentAPI_NetflowWriteStreamClient, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.firstSendError {
		n.firstSendError = false
	}
	s := &mockNetflowStreamClient{firstSendError: n.firstSendError}
	n.streams = append(n.streams, s)
	return s, nil
}

type mockNetflowStreamClient struct {
	mu sync.Mutex

	flows          []*castaipb.Netflow
	firstSendError bool
}

func (m *mockNetflowStreamClient) SendMsg(msg any) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.firstSendError {
		m.firstSendError = false
		return errors.New("can't send")
	}

	m.flows = append(m.flows, msg.(*castaipb.Netflow))
	return nil
}

func (m *mockNetflowStreamClient) CloseSend() error {
	return nil
}

func (m *mockNetflowStreamClient) Send(netflow *castaipb.Netflow) error {
	//TODO implement me
	panic("implement me")
}

func (m *mockNetflowStreamClient) CloseAndRecv() (*castaipb.WriteStreamResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (m *mockNetflowStreamClient) Header() (metadata.MD, error) {
	//TODO implement me
	panic("implement me")
}

func (m *mockNetflowStreamClient) Trailer() metadata.MD {
	//TODO implement me
	panic("implement me")
}

func (m *mockNetflowStreamClient) Context() context.Context {
	//TODO implement me
	panic("implement me")
}

func (m *mockNetflowStreamClient) RecvMsg(msg any) error {
	//TODO implement me
	panic("implement me")
}
