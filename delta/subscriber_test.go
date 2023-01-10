package delta

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/castai/kvisor/castai"
)

func TestSubscriber(t *testing.T) {
	r := require.New(t)
	ctx := context.Background()
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	castaiClient := &mockCastaiClient{}

	pod1 := &corev1.Pod{
		TypeMeta: metav1.TypeMeta{Kind: "Pod", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx-1",
			Namespace: "default",
			UID:       types.UID("111b56a9-ab5e-4a35-93af-f092e2f63011"),
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "v1",
					Kind:       kindNode,
					Controller: lo.ToPtr(true),
					Name:       "node1",
				},
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "n1",
			Containers: []corev1.Container{
				{
					Name:  "nginx",
					Image: "nginx:1.23",
				},
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
		},
	}

	assertDelta := func(t *testing.T, delta *castai.Delta, event castai.EventType, initial bool) {
		r := require.New(t)
		r.Equal(&castai.Delta{
			FullSnapshot: initial,
			Items: []castai.DeltaItem{
				{
					Event:            event,
					ObjectUID:        "111b56a9-ab5e-4a35-93af-f092e2f63011",
					ObjectName:       "nginx-1",
					ObjectNamespace:  "default",
					ObjectKind:       "Pod",
					ObjectAPIVersion: "v1",
					ObjectContainers: []castai.Container{
						{
							Name:      "nginx",
							ImageName: "nginx:1.23",
						},
					},
					ObjectStatus: corev1.PodStatus{Phase: corev1.PodRunning},
				},
			},
		}, delta)
	}

	t.Run("send add event", func(t *testing.T) {
		sub := NewSubscriber(log, logrus.DebugLevel, Config{DeltaSyncInterval: 1 * time.Millisecond}, castaiClient, &snapshotProviderMock{}, 21)
		sub.OnAdd(pod1)

		ctx, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
		defer cancel()
		err := sub.Run(ctx)
		r.True(errors.Is(err, context.DeadlineExceeded))
		delta := castaiClient.delta
		r.NotNil(delta)
		assertDelta(t, delta, castai.EventAdd, true)
	})

	t.Run("send update event", func(t *testing.T) {
		sub := NewSubscriber(log, logrus.DebugLevel, Config{DeltaSyncInterval: 1 * time.Millisecond}, castaiClient, &snapshotProviderMock{}, 21)
		sub.OnAdd(pod1)
		sub.OnUpdate(pod1)

		ctx, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
		defer cancel()
		err := sub.Run(ctx)
		r.True(errors.Is(err, context.DeadlineExceeded))
		delta := castaiClient.delta
		r.NotNil(delta)
		assertDelta(t, delta, castai.EventUpdate, true)
	})

	t.Run("send delete event", func(t *testing.T) {
		sub := NewSubscriber(log, logrus.DebugLevel, Config{DeltaSyncInterval: 1 * time.Millisecond}, castaiClient, &snapshotProviderMock{}, 21)
		sub.OnAdd(pod1)
		sub.OnUpdate(pod1)
		sub.OnDelete(pod1)

		ctx, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
		defer cancel()
		err := sub.Run(ctx)
		r.True(errors.Is(err, context.DeadlineExceeded))
		delta := castaiClient.delta
		r.NotNil(delta)
		assertDelta(t, delta, castai.EventDelete, true)
	})

	t.Run("second event does not set full snapshot flag", func(t *testing.T) {
		sub := NewSubscriber(log, logrus.DebugLevel, Config{DeltaSyncInterval: 1 * time.Millisecond}, castaiClient, &snapshotProviderMock{}, 21)
		sub.OnAdd(pod1)

		go func() {
			time.Sleep(time.Millisecond * 10)
			sub.OnAdd(pod1)
		}()

		ctx, cancel := context.WithTimeout(ctx, time.Millisecond*30)
		defer cancel()
		err := sub.Run(ctx)
		r.True(errors.Is(err, context.DeadlineExceeded))
		delta := castaiClient.delta
		r.NotNil(delta)
		assertDelta(t, delta, castai.EventAdd, false)
	})
}

type mockCastaiClient struct {
	delta *castai.Delta
}

func (m *mockCastaiClient) SendDeltaReport(ctx context.Context, report *castai.Delta) error {
	m.delta = report
	return nil
}

type snapshotProviderMock struct {
	items []castai.DeltaItem
}

func (s *snapshotProviderMock) append(item castai.DeltaItem) {
	s.items = append(s.items, item)
}

func (s *snapshotProviderMock) snapshot() []castai.DeltaItem {
	return s.items
}
