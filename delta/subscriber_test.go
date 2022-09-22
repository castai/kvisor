package delta

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/castai/sec-agent/castai"
)

func TestSubscriber(t *testing.T) {
	r := require.New(t)
	ctx := context.Background()
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	castaiClient := &mockCastaiClient{}

	sub := NewSubscriber(log, Config{DeltaSyncInterval: 1 * time.Millisecond}, castaiClient)

	pod1 := &corev1.Pod{
		TypeMeta: metav1.TypeMeta{Kind: "Pod", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx-1",
			Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "v1",
					Kind:       "Node",
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
	}

	sub.OnAdd(pod1)
	sub.OnUpdate(pod1)

	ctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	err := sub.Run(ctx)
	r.True(errors.Is(err, context.DeadlineExceeded))
	delta := castaiClient.delta
	r.NotNil(delta)
	r.Equal("", delta)
}

type mockCastaiClient struct {
	delta *castai.Delta
}

func (m *mockCastaiClient) SendDelta(ctx context.Context, delta *castai.Delta) error {
	m.delta = delta
	return nil
}
