package imagescan

import (
	"context"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestSubscriber(t *testing.T) {
	r := require.New(t)
	ctx := context.Background()
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	pod1 := &corev1.Pod{
		TypeMeta: metav1.TypeMeta{Kind: "Pod", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx-1",
			Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "apps/v1",
					Kind:       "ReplicaSet",
					Name:       "nginx-abc1",
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

	pod2 := &corev1.Pod{
		TypeMeta: metav1.TypeMeta{Kind: "Pod", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx-2",
			Namespace: "kube-system",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "apps/v1",
					Kind:       "ReplicaSet",
					Name:       "nginx-abc1",
				},
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "n2",
			Containers: []corev1.Container{
				{
					Name:  "nginx",
					Image: "nginx:1.23",
				},
			},
		},
		Status: corev1.PodStatus{},
	}

	pod3 := &corev1.Pod{
		TypeMeta: metav1.TypeMeta{Kind: "Pod", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "argocd",
			Namespace: "argo",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "apps/v1",
					Kind:       "ReplicaSet",
					Name:       "argocd-a123",
				},
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "n2",
			Containers: []corev1.Container{
				{
					Name:  "argocd",
					Image: "argocd:0.0.1",
				},
			},
		},
		Status: corev1.PodStatus{},
	}

	cfg := Config{ScanInterval: 1 * time.Millisecond}

	scanner := &mockImageScanner{}
	sub := NewSubscriber(log, cfg, scanner)
	ctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()

	sub.OnAdd(pod1)
	sub.OnAdd(pod2)
	sub.OnAdd(pod3)
	err := sub.Run(ctx)
	r.True(errors.Is(err, context.DeadlineExceeded))

	sort.Slice(scanner.imgs, func(i, j int) bool {
		return scanner.imgs[i].ImageName < scanner.imgs[j].ImageName
	})
	r.Equal("argocd:0.0.1", scanner.imgs[0].ImageName)
	r.Equal("nginx:1.23", scanner.imgs[1].ImageName)
	// TODO: Assert selected nodes.
}

type mockImageScanner struct {
	mu   sync.Mutex
	imgs []ScanImageConfig
}

func (m *mockImageScanner) ScanImage(ctx context.Context, cfg ScanImageConfig) (err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.imgs = append(m.imgs, cfg)
	sort.Slice(m.imgs, func(i, j int) bool {
		return m.imgs[i].ImageName > m.imgs[j].ImageName
	})
	return nil
}
