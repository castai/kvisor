package kubebench

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	mock_castai "github.com/castai/sec-agent/castai/mock"
	"github.com/castai/sec-agent/log"
)

func TestSubscriber(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	t.Run("creates job and sends report from log reader", func(t *testing.T) {
		mockctrl := gomock.NewController(t)
		r := require.New(t)
		ctx := context.Background()
		clientset := fake.NewSimpleClientset()
		mockCast := mock_castai.NewMockClient(mockctrl)

		logProvider := newMockLogProvider(readReport())

		subscriber := &Subscriber{
			log:          log,
			client:       clientset,
			delta:        newDeltaState(),
			provider:     "gke",
			logsProvider: logProvider,
			castClient:   mockCast,
		}

		jobName := "kube-bench-node-test_node"

		// fake clientset doesn't create pod for job
		_, err := clientset.CoreV1().Pods(castAINamespace).Create(ctx,
			&corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						labelJobName: jobName,
					},
					Namespace: castAINamespace,
				},
				Status: corev1.PodStatus{
					Phase: corev1.PodSucceeded,
				},
			}, metav1.CreateOptions{})
		r.NoError(err)

		node := &corev1.Node{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Node",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "test_node",
				UID:  types.UID(uuid.NewString()),
			},
		}
		mockCast.EXPECT().SendCISReport(gomock.Any(), gomock.Any())

		err = subscriber.lintNode(ctx, node)
		r.NoError(err)

		// job should be deleted
		_, err = clientset.BatchV1().Jobs(castAINamespace).Get(ctx, jobName, metav1.GetOptions{})
		r.Error(err)
	})

	t.Run("works only with nodes", func(t *testing.T) {
		r := require.New(t)
		subscriber := &Subscriber{
			log:      log,
			client:   nil,
			delta:    newDeltaState(),
			provider: "gke",
		}

		node := &corev1.Node{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Node",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "test_node",
			},
		}

		pod := &corev1.Pod{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Pod",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "test_pod",
			},
		}

		subscriber.OnAdd(node)
		subscriber.OnAdd(pod)

		r.Len(subscriber.delta.objectMap, 1)
	})
}

type mockProvider struct {
	logs []byte
}

func newMockLogProvider(b []byte) log.PodLogProvider {
	return &mockProvider{logs: b}
}

func (m *mockProvider) GetLogReader(_ context.Context, _, _ string) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(m.logs)), nil
}

func readReport() []byte {
	file, _ := os.OpenFile("../../testdata/kube-bench-gke.json", os.O_RDONLY, 0666)
	reportBytes, _ := io.ReadAll(file)

	return reportBytes
}
