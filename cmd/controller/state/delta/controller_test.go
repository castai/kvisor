package delta

import (
	"context"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/controller/kube"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/samber/lo"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
)

func TestController(t *testing.T) {
	defer goleak.VerifyNone(t)

	ctx := context.Background()
	log := logging.NewTestLog()

	dep1 := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx-1",
			Namespace: "default",
			UID:       types.UID("111b56a9-ab5e-4a35-93af-f092e2f63011"),
			OwnerReferences: []metav1.OwnerReference{
				{
					UID:        types.UID("owner"),
					APIVersion: "v1",
					Kind:       "Node",
					Controller: lo.ToPtr(true),
					Name:       "node1",
				},
			},
			Labels: map[string]string{"subscriber": "test"},
		},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					NodeName: "n1",
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.23",
						},
					},
				},
			},
		},
		Status: appsv1.DeploymentStatus{
			Replicas: 1,
		},
	}

	assertDelta := func(t *testing.T, delta *castaipb.KubernetesDeltaItem, event castaipb.KubernetesDeltaItemEvent, initial bool) {
		t.Helper()
		r := require.New(t)
		podUID := "111b56a9-ab5e-4a35-93af-f092e2f63011"
		expected, err := protojson.MarshalOptions{Multiline: true}.Marshal(&castaipb.KubernetesDeltaItem{
			Event:            event,
			ObjectUid:        podUID,
			ObjectName:       "nginx-1",
			ObjectNamespace:  "default",
			ObjectKind:       "Deployment",
			ObjectApiVersion: "v1",
			ObjectCreatedAt:  delta.ObjectCreatedAt,
			ObjectLabels:     map[string]string{"subscriber": "test"},
			ObjectContainers: []*castaipb.Container{
				{
					Name:      "nginx",
					ImageName: "nginx:1.23",
				},
			},
			ObjectStatus:   []byte(`{"replicas":1}`),
			ObjectOwnerUid: "111b56a9-ab5e-4a35-93af-f092e2f63011",
			ObjectSpec:     []byte(`{"selector":null,"template":{"metadata":{"creationTimestamp":null},"spec":{"containers":[{"name":"nginx","image":"nginx:1.23","resources":{}}],"nodeName":"n1"}},"strategy":{}}`),
		})
		r.NoError(err)

		actual, err := protojson.MarshalOptions{Multiline: true}.Marshal(delta)
		r.NoError(err)

		r.Equal(string(expected), string(actual))
	}

	t.Run("send add event", func(t *testing.T) {
		r := require.New(t)

		client := newMockClient()
		ctrl := newTestController(log, client)
		ctrl.castaiClient = client
		ctrl.OnAdd(dep1)

		ctx, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
		defer cancel()
		err := ctrl.Run(ctx)
		r.ErrorIs(err, context.DeadlineExceeded)
		r.Len(client.deltas, 1)
		assertDelta(t, client.deltas[0], castaipb.KubernetesDeltaItemEvent_DELTA_ADD, true)
	})

	t.Run("send update event", func(t *testing.T) {
		r := require.New(t)

		client := newMockClient()
		ctrl := newTestController(log, client)
		ctrl.castaiClient = client

		ctrl.OnAdd(dep1)
		ctrl.OnUpdate(dep1)

		ctx, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
		defer cancel()
		err := ctrl.Run(ctx)
		r.ErrorIs(err, context.DeadlineExceeded)
		r.Len(client.deltas, 1)
		assertDelta(t, client.deltas[0], castaipb.KubernetesDeltaItemEvent_DELTA_UPDATE, true)
	})

	t.Run("send delete event", func(t *testing.T) {
		r := require.New(t)
		client := newMockClient()
		ctrl := newTestController(log, client)
		ctrl.castaiClient = client
		ctrl.OnAdd(dep1)
		ctrl.OnUpdate(dep1)
		ctrl.OnDelete(dep1)

		ctx, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
		defer cancel()
		err := ctrl.Run(ctx)
		r.ErrorIs(err, context.DeadlineExceeded)
		r.Len(client.deltas, 1)
		assertDelta(t, client.deltas[0], castaipb.KubernetesDeltaItemEvent_DELTA_REMOVE, true)
	})

	t.Run("second event does not set full snapshot flag", func(t *testing.T) {
		r := require.New(t)
		client := newMockClient()
		ctrl := newTestController(log, client)
		ctrl.castaiClient = client
		ctrl.OnAdd(dep1)

		go func() {
			time.Sleep(time.Millisecond * 20)
			ctrl.OnAdd(dep1)
		}()

		ctx, cancel := context.WithTimeout(ctx, time.Millisecond*30)
		defer cancel()
		err := ctrl.Run(ctx)
		r.ErrorIs(err, context.DeadlineExceeded)
		r.Len(client.deltas, 2)
		assertDelta(t, client.deltas[1], castaipb.KubernetesDeltaItemEvent_DELTA_ADD, false)
	})

	t.Run("add failed to send deltas back", func(t *testing.T) {
		r := require.New(t)
		client := newMockClient()
		var receivedDeltasCount int
		client.streamFunc = func() castaipb.RuntimeSecurityAgentAPI_KubernetesDeltaIngestClient {
			return &mockStream{
				onSend: func(item *castaipb.KubernetesDeltaItem) error {
					receivedDeltasCount++
					if receivedDeltasCount > 1 {
						return errors.New("ups")
					}
					return nil
				},
			}
		}

		ctrl := newTestController(log, client)

		ctrl.OnAdd(dep1)
		r.Len(ctrl.pendingItems, 1)
		r.NoError(ctrl.sendDeltas(ctx, false))
		r.Len(ctrl.pendingItems, 0)

		ctrl.OnAdd(dep1)
		r.Len(ctrl.pendingItems, 1)
		r.ErrorIs(ctrl.sendDeltas(ctx, false), context.DeadlineExceeded)
		r.Len(ctrl.pendingItems, 1)
	})

	t.Run("send multiple delta items", func(t *testing.T) {
		dep1 := &appsv1.Deployment{
			TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "dep1",
				Namespace: "default",
				UID:       types.UID("111b56a9-ab5e-4a35-93af-f092e2f63011"),
				Labels:    map[string]string{"l1": "v1"},
			},
		}
		dep2 := &appsv1.Deployment{
			TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "dep2",
				Namespace: "default",
				UID:       types.UID("111b56a9-ab5e-4a35-93af-f092e2f63012"),
				Labels:    map[string]string{"l2": "v2"},
			},
		}

		r := require.New(t)
		client := newMockClient()
		ctrl := newTestController(log, client)
		ctrl.castaiClient = client
		ctrl.OnAdd(dep1)
		ctrl.OnAdd(dep2)

		err := ctrl.sendDeltas(ctx, false)
		r.NoError(err)
		r.Len(client.deltas, 2)
		sort.Slice(client.deltas, func(i, j int) bool {
			return client.deltas[i].ObjectName < client.deltas[j].ObjectName
		})
		r.Equal(dep1.Labels, client.deltas[0].ObjectLabels)
		r.Equal(dep1.ObjectMeta.Name, client.deltas[0].ObjectName)
		r.Equal(dep2.Labels, client.deltas[1].ObjectLabels)
		r.Equal(dep2.ObjectMeta.Name, client.deltas[1].ObjectName)
	})
}

func newMockClient() *mockCastaiClient {
	client := &mockCastaiClient{}
	client.streamFunc = func() castaipb.RuntimeSecurityAgentAPI_KubernetesDeltaIngestClient {
		return &mockStream{
			onSend: func(item *castaipb.KubernetesDeltaItem) error {
				client.mu.Lock()
				defer client.mu.Unlock()
				client.deltas = append(client.deltas, item)
				return nil
			},
		}
	}
	return client
}

func newTestController(log *logging.Logger, client *mockCastaiClient) *Controller {
	return NewController(
		log,
		Config{Interval: 1 * time.Millisecond, InitialDeltay: 1 * time.Millisecond, SendTimeout: 10 * time.Millisecond},
		client,
		&mockPodOwnerGetter{},
	)
}

type mockPodOwnerGetter struct {
}

func (m *mockPodOwnerGetter) GetOwnerUID(obj kube.Object) string {
	return string(obj.GetUID())
}

type mockCastaiClient struct {
	deltas     []*castaipb.KubernetesDeltaItem
	mu         sync.Mutex
	streamFunc func() v1.RuntimeSecurityAgentAPI_KubernetesDeltaIngestClient
}

func (m *mockCastaiClient) KubernetesDeltaIngest(ctx context.Context, opts ...grpc.CallOption) (v1.RuntimeSecurityAgentAPI_KubernetesDeltaIngestClient, error) {
	return m.streamFunc(), nil
}

type mockStream struct {
	onSend func(item *castaipb.KubernetesDeltaItem) error
}

func (m *mockStream) Recv() (*castaipb.KubernetesDeltaIngestResponse, error) {
	return &castaipb.KubernetesDeltaIngestResponse{}, nil
}

func (m *mockStream) Send(item *castaipb.KubernetesDeltaItem) error {
	return m.onSend(item)
}

func (m *mockStream) CloseAndRecv() (*castaipb.KubernetesDeltaIngestResponse, error) {
	return nil, nil
}

func (m *mockStream) Header() (metadata.MD, error) {
	return nil, nil
}

func (m *mockStream) Trailer() metadata.MD {
	return nil
}

func (m *mockStream) CloseSend() error {
	return nil

}

func (m *mockStream) Context() context.Context {
	return nil

}

func (m *mockStream) SendMsg(mmsg any) error {
	return nil

}

func (m *mockStream) RecvMsg(mmsg any) error {
	return nil
}
