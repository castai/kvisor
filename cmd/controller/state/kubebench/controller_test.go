package kubebench

import (
	"bytes"
	"context"
	"io"
	"os"
	"reflect"
	"testing"
	"time"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"k8s.io/client-go/kubernetes"

	"github.com/castai/kvisor/cmd/controller/kube"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

var castaiNamespace = "castai-sec"

func TestSubscriber(t *testing.T) {
	t.Run("creates job and sends report from log reader", func(t *testing.T) {
		r := require.New(t)
		ctx := context.Background()
		clientset := fake.NewSimpleClientset()
		mockCast := &mockCastaiClient{}
		log := logging.NewTestLog()
		logProvider := newMockLogProvider(readReport())
		kubeCtrl := &mockKubeController{}

		ctrl := newTestController(log, clientset, mockCast, logProvider, kubeCtrl)
		ctrl.finishedJobDeleteWaitDuration = 0

		jobName := generateName("test_node")

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
		ctrl.OnAdd(node)

		ctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
		defer cancel()
		err = ctrl.Run(ctx)
		r.ErrorIs(err, context.DeadlineExceeded)
		// Job should be deleted.
		_, err = clientset.BatchV1().Jobs(castaiNamespace).Get(ctx, jobName, metav1.GetOptions{})
		r.Error(err)
		r.Equal([]reflect.Type{reflect.TypeOf(&corev1.Node{})}, ctrl.RequiredInformers())

		r.Len(mockCast.reports, 1)
	})

	t.Run("skip already scanned node", func(t *testing.T) {
		r := require.New(t)
		ctx := context.Background()
		clientset := fake.NewSimpleClientset()
		mockCast := &mockCastaiClient{}
		log := logging.NewTestLog()
		logProvider := newMockLogProvider(readReport())
		kubeCtrl := &mockKubeController{}

		ctrl := newTestController(log, clientset, mockCast, logProvider, kubeCtrl)
		nodeID := types.UID(uuid.NewString())
		ctrl.scannedNodes.Add(string(nodeID), struct{}{})

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
		ctrl.OnAdd(node)
		ctrl.OnUpdate(node)

		ctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
		defer cancel()
		err := ctrl.Run(ctx)
		r.ErrorIs(err, context.DeadlineExceeded)
	})

	t.Run("use cached report", func(t *testing.T) {
		r := require.New(t)
		ctx := context.Background()
		clientset := fake.NewSimpleClientset()
		mockCast := &mockCastaiClient{}

		log := logging.NewTestLog()
		logProvider := newMockLogProvider(readReport())
		kubeCtrl := &mockKubeController{}

		ctrl := newTestController(log, clientset, mockCast, logProvider, kubeCtrl)
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
		ctrl.kubeBenchReportsCache = map[uint64]*castaipb.KubeBenchReport{
			nodeGroupKey: {},
		}
		ctrl.OnAdd(node)
		ctrl.OnUpdate(node)

		ctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
		defer cancel()
		err := ctrl.Run(ctx)
		r.ErrorIs(err, context.DeadlineExceeded)
		r.Len(mockCast.reports, 1)
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

func newTestController(log *logging.Logger, clientset kubernetes.Interface, mockCast castaiClient, logProvider kube.PodLogProvider, kubeCtrl kubeController) *Controller {
	ctrl := NewController(
		log,
		clientset,
		Config{
			ScanInterval:  5 * time.Millisecond,
			CloudProvider: "gke",
			JobNamespace:  castaiNamespace,
		},
		mockCast,
		logProvider,
		kubeCtrl,
		nil,
	)
	return ctrl
}

func newMockLogProvider(b []byte) kube.PodLogProvider {
	return &mockProvider{logs: b}
}

type mockProvider struct {
	logs []byte
}

func (m *mockProvider) GetLogReader(_ context.Context, _, _ string) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(m.logs)), nil
}

func readReport() []byte {
	file, _ := os.OpenFile("./testdata/kube-bench-gke.json", os.O_RDONLY, 0666)
	reportBytes, _ := io.ReadAll(file)

	return reportBytes
}

type mockKubeController struct {
}

func (m *mockKubeController) GetKvisorAgentImageDetails() (kube.ImageDetails, bool) {
	return kube.ImageDetails{
		ImageName:        "kvisor",
		ImagePullSecrets: nil,
	}, true
}

func (m *mockKubeController) GetPodOwnerID(pod *corev1.Pod) string {
	return string(pod.UID)
}

type mockCastaiClient struct {
	reports []*castaipb.KubeBenchReport
}

func (m *mockCastaiClient) KubeBenchReportIngest(ctx context.Context, in *castaipb.KubeBenchReport, opts ...grpc.CallOption) (*castaipb.KubeBenchReportIngestResponse, error) {
	m.reports = append(m.reports, in)
	return &castaipb.KubeBenchReportIngestResponse{}, nil
}
