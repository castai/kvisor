package kubebench

import (
	"bytes"
	"context"
	"io"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/castai/kvisor/castai"

	mock_castai "github.com/castai/kvisor/castai/mock"
	agentlog "github.com/castai/kvisor/log"
)

func TestSubscriber(t *testing.T) {
	t.Run("creates job and sends report from log reader", func(t *testing.T) {
		mockctrl := gomock.NewController(t)
		r := require.New(t)
		ctx := context.Background()
		clientset := fake.NewSimpleClientset()
		mockCast := mock_castai.NewMockClient(mockctrl)

		log := logrus.New()
		log.SetLevel(logrus.DebugLevel)
		var logOutput bytes.Buffer
		log.SetOutput(&logOutput)
		logProvider := newMockLogProvider(readReport())

		castaiNamespace := "castai-sec"
		subscriber := NewSubscriber(
			log,
			clientset,
			castaiNamespace,
			"gke",
			5*time.Millisecond,
			mockCast,
			logProvider,
			nil,
		)
		subscriber.(*Subscriber).finishedJobDeleteWaitDuration = 0

		jobName := generateName("test_node")

		mockCast.EXPECT().SendCISReport(gomock.Any(), gomock.Any()).MinTimes(1)

		// fake clientset doesn't create pod for job
		_, err := clientset.CoreV1().Pods(castaiNamespace).Create(ctx,
			&corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						labelJobName: jobName,
					},
					Namespace: castaiNamespace,
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
			Status: corev1.NodeStatus{
				Conditions: []corev1.NodeCondition{
					{
						Type:   corev1.NodeReady,
						Status: corev1.ConditionTrue,
					},
				},
			},
		}
		subscriber.OnAdd(node)

		ctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
		defer cancel()
		err = subscriber.Run(ctx)
		r.ErrorIs(err, context.DeadlineExceeded)
		r.NotContainsf(logOutput.String(), "error", "logs containers error")
		// Job should be deleted.
		_, err = clientset.BatchV1().Jobs(castaiNamespace).Get(ctx, jobName, metav1.GetOptions{})
		r.Error(err)
		r.Equal([]reflect.Type{reflect.TypeOf(&corev1.Node{})}, subscriber.RequiredInformers())
	})

	t.Run("skip already scanned node", func(t *testing.T) {
		mockctrl := gomock.NewController(t)
		r := require.New(t)
		ctx := context.Background()
		clientset := fake.NewSimpleClientset()
		mockCast := mock_castai.NewMockClient(mockctrl)

		log := logrus.New()
		log.SetLevel(logrus.DebugLevel)
		var logOutput bytes.Buffer
		log.SetOutput(&logOutput)
		logProvider := newMockLogProvider(readReport())

		castaiNamespace := "castai-sec"
		subscriber := NewSubscriber(
			log,
			clientset,
			castaiNamespace,
			"gke",
			5*time.Millisecond,
			mockCast,
			logProvider,
			nil,
		)
		nodeID := types.UID(uuid.NewString())
		subscriber.(*Subscriber).scannedNodes.Add(string(nodeID), struct{}{})

		node := &corev1.Node{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Node",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "test_node",
				UID:  nodeID,
			},
			Status: corev1.NodeStatus{
				Conditions: []corev1.NodeCondition{
					{
						Type:   corev1.NodeReady,
						Status: corev1.ConditionTrue,
					},
				},
			},
		}
		subscriber.OnAdd(node)
		subscriber.OnUpdate(node, nil)

		ctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
		defer cancel()
		err := subscriber.Run(ctx)
		r.ErrorIs(err, context.DeadlineExceeded)
		r.NotContainsf(logOutput.String(), "error", "logs containers error")
	})

	t.Run("use cached report", func(t *testing.T) {
		mockctrl := gomock.NewController(t)
		r := require.New(t)
		ctx := context.Background()
		clientset := fake.NewSimpleClientset()
		mockCast := mock_castai.NewMockClient(mockctrl)

		log := logrus.New()
		log.SetLevel(logrus.DebugLevel)
		var logOutput bytes.Buffer
		log.SetOutput(&logOutput)
		logProvider := newMockLogProvider(readReport())

		castaiNamespace := "castai-sec"
		subscriber := NewSubscriber(
			log,
			clientset,
			castaiNamespace,
			"gke",
			5*time.Millisecond,
			mockCast,
			logProvider,
			nil,
		)
		nodeID := types.UID(uuid.NewString())
		node := &corev1.Node{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Node",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "test_node",
				UID:  nodeID,
			},
			Status: corev1.NodeStatus{
				Conditions: []corev1.NodeCondition{
					{
						Type:   corev1.NodeReady,
						Status: corev1.ConditionTrue,
					},
				},
			},
		}
		nodeGroupKey := getNodeGroupKey(node)
		subscriber.(*Subscriber).kubeBenchReportsCache = map[uint64]*castai.KubeBenchReport{
			nodeGroupKey: {},
		}
		subscriber.OnAdd(node)
		subscriber.OnUpdate(node, nil)

		mockCast.EXPECT().SendCISReport(gomock.Any(), gomock.Any()).MinTimes(1)

		ctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
		defer cancel()
		err := subscriber.Run(ctx)
		r.ErrorIs(err, context.DeadlineExceeded)
		r.NotContainsf(logOutput.String(), "error", "logs containers error")
	})
}

func TestNodeGroupKey(t *testing.T) {
	r := require.New(t)
	n1 := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"provisioner.cast.ai/node-configuration-name":    "default",
				"provisioner.cast.ai/node-configuration-version": "v1",
			},
		},
		Status: corev1.NodeStatus{
			NodeInfo: corev1.NodeSystemInfo{
				KernelVersion:           "k1",
				OSImage:                 "os1",
				ContainerRuntimeVersion: "containerd",
				KubeletVersion:          "kubelet 1.1.1",
				Architecture:            "amd64",
			},
		},
	}
	n2 := &corev1.Node{
		Status: corev1.NodeStatus{
			NodeInfo: corev1.NodeSystemInfo{
				KernelVersion:           "k2",
				OSImage:                 "os2",
				ContainerRuntimeVersion: "containerd",
				KubeletVersion:          "kubelet 2.2.2",
				Architecture:            "amd64",
			},
		},
	}

	key1 := getNodeGroupKey(n1)
	r.Equal(key1, getNodeGroupKey(n1))
	key2 := getNodeGroupKey(n2)
	r.NotEqual(key1, key2)
}

type mockProvider struct {
	logs []byte
}

func newMockLogProvider(b []byte) agentlog.PodLogProvider {
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
